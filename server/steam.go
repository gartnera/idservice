package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Jleagle/unmarshal-go"
)

type SteamClient struct {
	Key string
}

func (c SteamClient) getFromApi(path string, options url.Values) ([]byte, error) {
	if c.Key == "" {
		panic("steam key must be set")
	}
	options.Add("key", c.Key)
	req, err := http.NewRequest("GET", "https://api.steampowered.com/"+path+"?"+options.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (c SteamClient) GetPlayer(playerID int64) (player PlayerSummary, err error) {

	options := url.Values{}
	options.Set("steamids", strconv.FormatInt(playerID, 10))

	b, err := c.getFromApi("ISteamUser/GetPlayerSummaries/v2", options)
	if err != nil {
		return player, err
	}

	var resp PlayerResponse
	err = json.Unmarshal(b, &resp)
	if err != nil {
		return player, err
	}

	if len(resp.Response.Players) == 0 {
		return player, fmt.Errorf("no profile")
	}

	return resp.Response.Players[0], nil
}

type PlayerResponse struct {
	Response struct {
		Players []PlayerSummary `json:"players"`
	} `json:"response"`
}

type PlayerSummary struct {
	SteamID                  unmarshal.Int64 `json:"steamid"`
	CommunityVisibilityState int             `json:"communityvisibilitystate"`
	ProfileState             int             `json:"profilestate"`
	PersonaName              string          `json:"personaname"`
	LastLogOff               int64           `json:"lastlogoff"`
	CommentPermission        int             `json:"commentpermission"`
	ProfileURL               string          `json:"profileurl"`
	Avatar                   string          `json:"avatar"`
	AvatarMedium             string          `json:"avatarmedium"`
	AvatarFull               string          `json:"avatarfull"`
	AvatarHash               string          `json:"avatarhash"`
	PersonaState             int             `json:"personastate"`
	RealName                 string          `json:"realname"`
	PrimaryClanID            string          `json:"primaryclanid"`
	TimeCreated              int64           `json:"timecreated"`
	PersonaStateFlags        int             `json:"personastateflags"`
	CountryCode              string          `json:"loccountrycode"`
	StateCode                string          `json:"locstatecode"`
	CityID                   int             `json:"loccityid"`
}

// Return a list of games owned by the player
func (c SteamClient) GetOwnedGames(playerID int64, includeFree bool) (games OwnedGames, err error) {
	includeFreeOpt := "0"
	if includeFree {
		includeFreeOpt = "1"
	}
	options := url.Values{}
	options.Set("steamid", strconv.FormatInt(playerID, 10))
	options.Set("include_appinfo", "1")
	options.Set("include_played_free_games", includeFreeOpt)

	b, err := c.getFromApi("IPlayerService/GetOwnedGames/v1", options)
	if err != nil {
		return games, err
	}

	var resp OwnedGamesResponse
	err = json.Unmarshal(b, &resp)
	if err != nil {
		return games, err
	}

	return resp.Response, nil
}

type OwnedGamesResponse struct {
	Response OwnedGames `json:"response"`
}

type OwnedGames struct {
	GameCount int `json:"game_count"`
	Games     []struct {
		AppID                    int    `json:"appid"`
		Name                     string `json:"name"`
		PlaytimeForever          int    `json:"playtime_forever"`
		PlaytimeWindows          int    `json:"playtime_windows_forever"`
		PlaytimeMac              int    `json:"playtime_mac_forever"`
		PlaytimeLinux            int    `json:"playtime_linux_forever"`
		ImgIconURL               string `json:"img_icon_url"`
		ImgLogoURL               string `json:"img_logo_url"`
		HasCommunityVisibleStats bool   `json:"has_community_visible_stats"`
	} `json:"games"`
}

// Returns the Steam Level of a user
func (c SteamClient) GetSteamLevel(playerID int64) (level int, err error) {

	options := url.Values{}
	options.Set("steamid", strconv.FormatInt(playerID, 10))

	b, err := c.getFromApi("IPlayerService/GetSteamLevel/v1", options)
	if err != nil {
		return level, err
	}

	var resp LevelResponse
	err = json.Unmarshal(b, &resp)
	if err != nil {
		return level, err
	}

	return resp.Response.PlayerLevel, nil
}

type LevelResponse struct {
	Response struct {
		PlayerLevel int `json:"player_level"`
	} `json:"response"`
}
