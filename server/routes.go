package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-fuego/fuego"
	"github.com/gorilla/securecookie"
	"github.com/lithammer/shortuuid"
	"github.com/yohcop/openid-go"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
)

const (
	steamOpenID        = "https://steamcommunity.com/openid"
	steamCallbackUrl   = "/login/steam/callback"
	profileUrl         = "/profile"
	spotifyCallbackUrl = "/login/spotify/callback"
)

type routes struct {
	DB                 *gorm.DB
	SteamClient        SteamClient
	TelegramBotToken   string
	SecureCookie       *securecookie.SecureCookie
	SpotifyOauthConfig oauth2.Config
}

func (r *routes) RegisterRoutes(s *fuego.Server) {
	fuego.Get(s, "/", r.Home)
	fuego.Get(s, "/hello", r.Hello)

	fuego.Post(s, "/login/steam", r.LoginSteam)
	fuego.Get(s, steamCallbackUrl, r.LoginSteamCallback)
	fuego.Get(s, "/login/telegram/callback", r.LoginTelegramCallback)
	fuego.Get(s, "/login/spotify", r.LoginSpotify)
	fuego.Get(s, "/login/spotify/callback", r.LoginSpotifyCallback)
	fuego.Get(s, "/logout", r.Logout)

	fuego.Get(s, profileUrl, r.Profile)
}

type HelloResponse struct {
	TimeLocal  time.Time `json:"time_local"`
	TimeUTC    time.Time `json:"time_utc"`
	RemoteAddr string    `json:"remote_addr"`
}

func (r *routes) Hello(c *fuego.ContextNoBody) (DataOrTemplate[HelloResponse], error) {
	resp := HelloResponse{
		TimeLocal:  time.Now(),
		TimeUTC:    time.Now().UTC(),
		RemoteAddr: c.Req.RemoteAddr,
	}

	return DataOrTemplate[HelloResponse]{
		Data:       resp,
		TemplateFn: renderHello,
	}, nil
}

func (r *routes) Home(c *fuego.ContextNoBody) (fuego.Gomponent, error) {
	return renderHome(), nil
}

func (r *routes) setLoginUidCookie(c *fuego.ContextNoBody, uid string) (any, error) {
	cookie, err := r.SecureCookie.Encode("uid", uid)
	if err != nil {
		panic(err)
	}
	c.SetCookie(http.Cookie{
		Name:     "uid",
		Value:    cookie,
		Path:     "/",
		HttpOnly: true,
	})
	return c.Redirect(http.StatusTemporaryRedirect, profileUrl)
}

func (r *routes) getLoginUidCookie(c *fuego.ContextNoBody) (string, error) {
	uidCookie, err := c.Cookie("uid")
	if err != nil {
		return "", fmt.Errorf("no uid cookie")
	}
	var uid string
	err = r.SecureCookie.Decode("uid", uidCookie.Value, &uid)
	if err != nil {
		return "", fmt.Errorf("invalid uid cookie")
	}
	return uid, nil
}

var discoveryCache = openid.NewSimpleDiscoveryCache()
var nonceStore = openid.NewSimpleNonceStore()

func calcCallbackUrl(c *fuego.ContextNoBody, uri string) string {
	host := c.Req.Host
	scheme := "https://"
	if strings.Contains(host, "localhost") {
		scheme = "http://"
	}
	return scheme + host + uri
}

func (r *routes) LoginSteam(c *fuego.ContextNoBody) (any, error) {
	callbackUrl := calcCallbackUrl(c, steamCallbackUrl)
	url, err := openid.RedirectURL(steamOpenID, callbackUrl, "")
	if err != nil {
		return nil, err
	}
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func (r *routes) LoginSteamCallback(c *fuego.ContextNoBody) (any, error) {
	url := c.Req.URL.String()
	fmt.Println(url)
	rawId, err := openid.Verify(url, discoveryCache, nonceStore)
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("verifying callback: %w", err)), nil
	}
	log.Printf("got steam login with id: %v", rawId)

	_, idString := path.Split(rawId)

	playerID, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		log.Printf("%s id not a valid int", idString)
		return nil, err
	}

	idHashBytes := sha256.Sum256([]byte(idString))
	idHash := hex.EncodeToString(idHashBytes[:])

	currentUid, currentUidErr := r.getLoginUidCookie(c)

	challengeRecord := &ChallengeRecord{}
	r.DB.First(&challengeRecord, "service = 'steam' AND service_id_hash = ?", idHash)
	if challengeRecord.UserID != "" {
		log.Printf("found existing user %s", challengeRecord.UserID)
		if currentUidErr == nil && challengeRecord.UserID != currentUid {
			c.Response().WriteHeader(http.StatusBadRequest)
			return renderLoginFailed(fmt.Errorf("account already linked")), nil
		}
		return r.setLoginUidCookie(c, challengeRecord.UserID)
	}

	// TODO: skip this if user found

	playerSummary, err := r.SteamClient.GetPlayer(playerID)
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("get player: %w", err)), nil
	}
	if playerSummary.CommunityVisibilityState != 3 {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(errors.New("Profile is not public")), nil
	}

	// truncate timestamp for privacy
	serviceCreatedTime := time.Unix(playerSummary.TimeCreated, 0).Truncate(time.Hour * 24)

	ownedGames, err := r.SteamClient.GetOwnedGames(playerID, false)
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("get owned games: %w", err)), nil
	}
	ownedGamesCount := len(ownedGames.Games)
	isPremium := ownedGamesCount > 1
	// round to nearest 10 for privacy
	ownedGamesCountPrivate := ((ownedGamesCount + 5) / 10) * 10

	log.Printf("got user info. created: %v, isPremium: %v", playerSummary.TimeCreated, isPremium)

	userId := currentUid
	if currentUidErr != nil {
		userId = shortuuid.New()
	}

	challengeRecord = &ChallengeRecord{
		UserID:           userId,
		CreatedAt:        time.Now(),
		Service:          "steam",
		ServiceIDHash:    idHash,
		ServiceCreated:   serviceCreatedTime,
		IsPremium:        isPremium,
		TransactionCount: ownedGamesCountPrivate,
	}
	r.DB.Create(challengeRecord)
	log.Printf("created user %s", challengeRecord.UserID)
	return r.setLoginUidCookie(c, challengeRecord.UserID)
}

// Response represents the structure of the API response
type TelegramGetChatResponse struct {
	Ok     bool             `json:"ok"`
	Result TelegramChatInfo `json:"result"`
}

// ChatInfo represents the structure of the chat information
type TelegramChatInfo struct {
	ID               int64    `json:"id"`
	FirstName        string   `json:"first_name"`
	LastName         string   `json:"last_name"`
	Username         string   `json:"username"`
	Type             string   `json:"type"`
	ActiveUsernames  []string `json:"active_usernames"`
	MaxReactionCount int      `json:"max_reaction_count"`
	AccentColorID    int      `json:"accent_color_id"`
	IsPremium        bool     `json:"is_premium"`
}

func (r *routes) getTelegramPremiumStatus(id string) bool {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getChat?chat_id=%s", r.TelegramBotToken, id)
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Telegram get chat info failed with status code: %d", resp.StatusCode)
		return false
	}

	var response TelegramGetChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false
	}
	return response.Result.IsPremium
}

func (r *routes) LoginTelegramCallback(c *fuego.ContextNoBody) (any, error) {
	params := c.Req.URL.Query()
	// Extract the `hash` from the query params
	hash := params.Get("hash")
	params.Del("hash") // Remove `hash` from params

	// Sort the remaining parameters
	var sortedParams []string
	for key, value := range params {
		sortedParams = append(sortedParams, fmt.Sprintf("%s=%s", key, value[0]))
	}
	sort.Strings(sortedParams)

	// Create the data_check_string
	dataCheckString := strings.Join(sortedParams, "\n")

	// Generate the secret key
	secretKey := sha256.Sum256([]byte(r.TelegramBotToken))

	// Compute the HMAC-SHA256 hash using the secret key
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(dataCheckString))
	computedHash := hex.EncodeToString(h.Sum(nil))

	if hash != computedHash {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("hash mismatch when verifying callback")), nil
	}

	// TODO: maybe we need username too?
	idString := params.Get("id")
	idHashBytes := sha256.Sum256([]byte(idString))
	idHash := hex.EncodeToString(idHashBytes[:])

	currentUid, currentUidErr := r.getLoginUidCookie(c)

	challengeRecord := &ChallengeRecord{}
	r.DB.First(&challengeRecord, "service = 'telegram' AND service_id_hash = ?", idHash)
	if challengeRecord.UserID != "" {
		log.Printf("found existing user %s", challengeRecord.UserID)
		if currentUidErr == nil && challengeRecord.UserID != currentUid {
			c.Response().WriteHeader(http.StatusBadRequest)
			return renderLoginFailed(fmt.Errorf("account already linked")), nil
		}
		return r.setLoginUidCookie(c, challengeRecord.UserID)
	}

	userId := currentUid
	if currentUidErr != nil {
		userId = shortuuid.New()
	}

	// attempt to get premium status
	// this will fail if the user did not grant permission to chat
	isPremium := r.getTelegramPremiumStatus(idString)

	challengeRecord = &ChallengeRecord{
		UserID:        userId,
		CreatedAt:     time.Now(),
		Service:       "telegram",
		ServiceIDHash: idHash,
		IsPremium:     isPremium,
	}
	r.DB.Create(challengeRecord)

	return r.setLoginUidCookie(c, userId)
}

func (r *routes) LoginSpotify(c *fuego.ContextNoBody) (any, error) {
	if r.SpotifyOauthConfig.RedirectURL == "" {
		r.SpotifyOauthConfig.RedirectURL = calcCallbackUrl(c, spotifyCallbackUrl)
	}
	url := r.SpotifyOauthConfig.AuthCodeURL("")
	return c.Redirect(http.StatusPermanentRedirect, url)
}

const spotifyPlaylistsURL = "https://api.spotify.com/v1/me/playlists?limit=50"

type PlaylistResponse struct {
	Href     string         `json:"href"`
	Limit    int            `json:"limit"`
	Next     string         `json:"next"`
	Offset   int            `json:"offset"`
	Previous string         `json:"previous"`
	Total    int            `json:"total"`
	Items    []PlaylistItem `json:"items"`
}

type PlaylistOwner struct {
	ID string `json:"id"`
}

type PlaylistItem struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Owner       PlaylistOwner `json:"owner"`
	URI         string        `json:"uri"`
}

type SpotifyPlaylistTracks struct {
	Items []struct {
		AddedAt time.Time `json:"added_at"`
		AddedBy struct {
			ExternalUrls struct {
				Spotify string `json:"spotify"`
			} `json:"external_urls"`
			Href string `json:"href"`
			ID   string `json:"id"`
			Type string `json:"type"`
			URI  string `json:"uri"`
		} `json:"added_by"`
	} `json:"items"`
}

func getSpotifyPlaylists(client *http.Client, url string) (*PlaylistResponse, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	var playlistResponse PlaylistResponse
	if err := json.NewDecoder(resp.Body).Decode(&playlistResponse); err != nil {
		return nil, err
	}

	return &playlistResponse, nil
}

func getSpotifyPlaylistTracks(client *http.Client, id string) (*SpotifyPlaylistTracks, error) {
	// note: this is missing pagination
	url := fmt.Sprintf("https://api.spotify.com/v1/playlists/%s/tracks?limit=50&items(added_by,added_at)", id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	playlistTracks := &SpotifyPlaylistTracks{}
	if err := json.NewDecoder(resp.Body).Decode(&playlistTracks); err != nil {
		return nil, err
	}
	return playlistTracks, nil
}

func getSpotifyMinimumPlaylistTime(client *http.Client, userID string) (*time.Time, error) {
	nextURL := spotifyPlaylistsURL

	minTime := time.Now()
	minTimeLock := sync.RWMutex{}
	eg := errgroup.Group{}
	eg.SetLimit(6)
	for nextURL != "" {
		playlistResponse, err := getSpotifyPlaylists(client, nextURL)
		if err != nil {
			return nil, err
		}

		for _, playlist := range playlistResponse.Items {
			if playlist.Owner.ID != userID {
				continue
			}
			playlist := playlist
			eg.Go(func() error {
				playlistTracks, err := getSpotifyPlaylistTracks(client, playlist.ID)
				if err != nil {
					return fmt.Errorf("get spotify playlist tracks: %w", err)
				}
				for _, track := range playlistTracks.Items {
					if track.AddedBy.ID != userID {
						continue
					}
					addedAt := track.AddedAt
					if addedAt.IsZero() {
						continue
					}
					minTimeLock.RLock()

					shouldUpdate := addedAt.Before(minTime)
					minTimeLock.RUnlock()
					if !shouldUpdate {
						continue
					}
					minTimeLock.Lock()
					minTime = addedAt
					minTimeLock.Unlock()
				}
				return nil
			})

		}

		nextURL = playlistResponse.Next
	}
	err := eg.Wait()
	return &minTime, err
}

type SpotifyUserInfo struct {
	Country     string `json:"country"`
	DisplayName string `json:"display_name"`
	Href        string `json:"href"`
	ID          string `json:"id"`
	Product     string `json:"product"`
	Type        string `json:"type"`
	URI         string `json:"uri"`
}

func (r *routes) LoginSpotifyCallback(c *fuego.ContextNoBody) (any, error) {
	code := c.QueryParam("code")
	if r.SpotifyOauthConfig.RedirectURL == "" {
		r.SpotifyOauthConfig.RedirectURL = calcCallbackUrl(c, spotifyCallbackUrl)
	}
	token, err := r.SpotifyOauthConfig.Exchange(c.Context(), code)
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("verifying callback: %w", err)), nil
	}

	client := r.SpotifyOauthConfig.Client(c.Context(), token)
	userInfoResp, err := client.Get("https://api.spotify.com/v1/me")
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("getting user info: %w", err)), nil
	}
	defer userInfoResp.Body.Close()

	var userInfo SpotifyUserInfo
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("decoding user info: %w", err)), nil
	}

	idHashBytes := sha256.Sum256([]byte(userInfo.ID))
	idHash := hex.EncodeToString(idHashBytes[:])
	currentUid, currentUidErr := r.getLoginUidCookie(c)

	challengeRecord := &ChallengeRecord{}
	r.DB.First(&challengeRecord, "service = 'spotify' AND service_id_hash = ?", idHash)
	if challengeRecord.UserID != "" {
		log.Printf("found existing spotify user %s", challengeRecord.UserID)
		if currentUidErr == nil && challengeRecord.UserID != currentUid {
			c.Response().WriteHeader(http.StatusBadRequest)
			return renderLoginFailed(fmt.Errorf("account already linked")), nil
		}
		return r.setLoginUidCookie(c, challengeRecord.UserID)
	}

	minTime, err := getSpotifyMinimumPlaylistTime(client, userInfo.ID)
	if err != nil {
		c.Response().WriteHeader(http.StatusBadRequest)
		return renderLoginFailed(fmt.Errorf("get minimum playlist time: %w", err)), nil
	}
	log.Printf("got spotify minimum time: %v", minTime)

	userId := currentUid
	if currentUidErr != nil {
		userId = shortuuid.New()
	}

	isPremium := userInfo.Product == "premium"

	challengeRecord = &ChallengeRecord{
		UserID:         userId,
		CreatedAt:      time.Now(),
		ServiceCreated: *minTime,
		Service:        "spotify",
		ServiceIDHash:  idHash,
		IsPremium:      isPremium,
	}
	r.DB.Create(challengeRecord)

	return r.setLoginUidCookie(c, userId)
}

func (r *routes) Logout(c *fuego.ContextNoBody) (any, error) {
	// expire uid cookie
	c.SetCookie(http.Cookie{
		Name:     "uid",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(-time.Hour),
	})
	return c.Redirect(http.StatusTemporaryRedirect, "/")
}

type ProfileResponse struct {
	ID         string
	Challenges []ChallengeRecord
}

func (r *routes) Profile(c *fuego.ContextNoBody) (*DataOrTemplate[ProfileResponse], error) {
	uid, err := r.getLoginUidCookie(c)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return nil, err
	}
	resp := ProfileResponse{
		ID: uid,
	}
	r.DB.Find(&resp.Challenges, "user_id = ?", uid)
	return &DataOrTemplate[ProfileResponse]{
		Data:       resp,
		TemplateFn: renderProfile,
	}, nil
}
