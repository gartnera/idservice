package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/go-fuego/fuego"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	s := fuego.NewServer()

	// TODO: conditional enable
	fuego.Use(s, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			via := r.Header.Get("Via")
			if via != "" {
				viaHost := strings.Split(via, " ")[1]
				r.Host = viaHost
				r.URL.Scheme = "https"
				r.URL.Host = viaHost
			}
			next.ServeHTTP(w, r)
		})
	})

	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	Migrate(db)

	steamClient := SteamClient{
		Key: os.Getenv("STEAM_API_KEY"),
	}
	r := routes{
		DB:               db,
		SteamClient:      steamClient,
		TelegramBotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		SecureCookie:     securecookie.New([]byte("42D794DD9F6F8390465D2454E75B542D"), []byte("42D794DD9F6F8390465D2454E75B542D")),
		SpotifyOauthConfig: oauth2.Config{
			ClientID:     os.Getenv("SPOTIFY_CLIENT_ID"),
			ClientSecret: os.Getenv("SPOTIFY_CLIENT_SECRET"),
			Scopes:       []string{"user-read-private", "playlist-read-private"},
			Endpoint:     spotify.Endpoint,
		},
	}
	r.RegisterRoutes(s)

	s.Run()
}
