package main

import (
	"strconv"
	"time"

	"github.com/go-fuego/fuego"
	. "maragu.dev/gomponents"
	. "maragu.dev/gomponents/html"
)

func base(title string, children ...Node) Node {
	return HTML(
		Attr("lang", "en"),
		Data("bs-theme", "dark"),
		Head(
			Meta(Attr("charset", "utf-8")),
			Meta(Attr("name", "viewport"), Attr("content", "width=device-width, initial-scale=1")),
			TitleEl(Text(title)),
			Link(
				Attr("href", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"),
				Attr("rel", "stylesheet"),
				Attr("integrity", "sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"),
				Attr("crossorigin", "anonymous"),
			),
			Script(
				Attr("src", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"),
				Attr("integrity", "sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"),
				Attr("async"),
				Attr("crossorigin", "anonymous"),
			),
		),
		Body(
			Class("container"),
			Class("py-5"),
			Div(children...),
		),
	)
}

func renderHome() fuego.Gomponent {
	return base(
		"Profile Challenges",
		H1(Text("Profile Challenges")),
		Div(
			P((Text("This application allows you to demonstrate trustworthiness by completing challenges."))),
			P((Text("We preserve your privacy by only storing a hash of your information."))),
		),
		Div(
			H2(Text("Get Started")),
			P(Text("Select a social provider to login:")),
			H3(Text("Steam")),
			P(Text("Your profile must be set to public during your first login. You may set it to private again after login.")),
			Form(
				Action("/login/steam"),
				Method("post"),
				Button(
					Type("submit"),
					Style("background:none;border:none;padding:0"),
					Img(
						Src("https://community.fastly.steamstatic.com/public/images/signinthroughsteam/sits_01.png"),
						Width("180"),
						Height("35"),
						Style("border:0"),
						Alt("Sign in through Steam"),
					),
				),
			),
			H3(Text("Telegram")),
			P(Text("You must grant access to send messages if you'd like your premium status to be verified.")),
			Raw(`<script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="agartner_test_bot" data-size="large" data-auth-url="https://pc.t.agartner.com/login/telegram/callback" data-request-access="write"></script>`),
		),
	)
}

func renderLoginFailed(err error) fuego.Gomponent {
	return base(
		"Profile Challenges - Login Failed",
		H1(Text("Login Failed")),
		Div(
			P(Text(err.Error())),
			A(
				Text("Return home"),
				Href("/"),
			),
		),
	)
}

func renderHello(resp HelloResponse) fuego.Gomponent {
	return base(
		"hello",
		H1(Text("Hello user!")),
		H2(Text("Remote Address")),
		P(Text(resp.RemoteAddr)),
		H2(Text("Local Time")),
		P(Text(resp.TimeLocal.String())),
		H2(Text("UTC Time")),
		P(Text(resp.TimeUTC.String())),
	)
}

func renderTimestampMinimal(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

func renderProfile(resp ProfileResponse) fuego.Gomponent {
	return base(
		"Your Profile",
		H1(Textf("User profile for %s", resp.ID)),
		Table(
			Class("table"),
			THead(
				Class("table-dark"),
				Th(Text("Service")),
				Th(Text("Service Created At")),
				Th(Text("Verified At")),
				Th(Text("Premium")),
				Th(Text("Transaction Count")),
			),
			TBody(
				Map(resp.Challenges, func(t ChallengeRecord) Node {
					return Tr(
						Td(Text(t.Service)),
						Td(Text(renderTimestampMinimal(t.ServiceCreated))),
						Td(Text(renderTimestampMinimal(t.CreatedAt))),
						Td(Text(strconv.FormatBool(t.IsPremium))),
						Td(Text(strconv.Itoa(t.TransactionCount))),
					)
				}),
			),
		),
	)
}
