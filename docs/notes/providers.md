# Providers

Providers fall under some different categories. By default, you must statisfy one provider in each category.

Some providers can satisfy multiple categories.

## Social

Social providers look for information from social accounts. We're mostly looking for phone number verification and profile age, but post count stats might be useful too.

We might want to pull verified emails eventually, but maybe we should just do that separately.

### Discord

| Phone Number Verification | Account Age | Premium Status |
|---------------------------|-------------|----------------|
|❌                         |✅           |✅              |

References:

- [get current user](https://discord.com/developers/docs/resources/user#get-current-user)
- [user object](https://discord.com/developers/docs/resources/user#user-object)
- [showflakes](https://discord.com/developers/docs/reference#snowflakes) allows you to get timestamp from ID

Could force the user to join a [Highest verfiication level server)[https://support.discord.com/hc/en-us/articles/216679607-Verification-Levels] to ensure verified email and phone.

### Telegram

| Phone Number Verification | Account Age | Premium Status |
|---------------------------|-------------|----------------|
|✅                         |❌           |✅              |

Telegram always requires a phone number. The [login widget](https://core.telegram.org/widgets/login) should phone number verification very easy.

The other items would require interacting with a telegram bot. Handle [message](https://core.telegram.org/bots/api#message) webhook, then get [user](https://core.telegram.org/bots/api#user).

Telegram IDs do seem to be sequential so theoretically you could derive general account age from that.

IDs from both my accounts (redacted):
```
58840057**
72341690**
```

### Twitter

| Phone Number Verification | Account Age | Premium Status |
|---------------------------|-------------|----------------|
|❌                         |✅           |✅              |


API [user object](https://developer.x.com/en/docs/x-api/users/lookup/api-reference/get-users-id) contains `created_at`. Use verified as premium status.

### Github

| Phone Number Verification | Account Age | Premium Status |
|---------------------------|-------------|----------------|
|❌                         |✅           |✅              |

[Get authenticated user](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user) returns `created_at`. `plan` will be premium status.

On the GraphQL API (ew), the [User object](https://docs.github.com/en/graphql/reference/objects#user) has a `sponsoring` field which is a [Sponsorship object](https://docs.github.com/en/graphql/reference/objects#sponsorship).

### Steam

| Phone Number Verification | Account Age | Premium Status |
|---------------------------|-------------|----------------|
|❌                         |✅           |✅              |

Steam is both a proof of social and proof of wallet, since you can use the [`GetOwnedGames`](https://partner.steamgames.com/doc/webapi/iplayerservice#GetOwnedGames) with the `include_played_free_games=false` option to derive the value of games on the account.

General account age can be determined via [`GetBadges`](https://api.steampowered.com/IPlayerService/GetBadges/v1) and looking at the years of service badge:

```
{
    "badgeid": 1,
    "level": 13,
    "completion_time": 1293676842,
    "xp": 650,
    "scarcity": 31385031
},
```

### Twitch

| Phone Number Verification | Account Age | Premium Status |
|---------------------------|-------------|----------------|
|❌                         |✅           |✅              |

[Get Users](https://dev.twitch.tv/docs/api/reference/#get-users) has `created_at` field on the user.

Premium status can be determined by pivoting from [followed streams](https://dev.twitch.tv/docs/api/reference/#get-followed-streams) or [user emotes](https://dev.twitch.tv/docs/api/reference/#get-user-emotes) to [user subscriptions](https://dev.twitch.tv/docs/api/reference/#check-user-subscription).

### wechat/weixin

Discord and telegram are banned in China so wechat might be useful. Weixin is the parent company.

Creating oauth application requires a business if you are not in mainland china.

### Apple

I thought sign in with Apple would be useful because of the `real_user_status` field. But it not avaliable on web-based apps.

### WhatsApp

Seems like dogshit business only thing. You have to have a dedicated phone number for your app?

### Facebook

All facebook apps seem to require business verification now?

[Scraper](https://apify.com/apify/facebook-posts-scraper)

Instagram scraper is cheaper and returns more data

### Instagram

[Profile scraper](https://apify.com/apify/instagram-profile-scraper)

[Post scraper](https://apify.com/apify/instagram-post-scraper)

## Hardware

### ftpm

Modern x86_64 processors have a firmware TPM that is embeded in the processor itself. TPMs have an endorsement key (EK) which is burned into the hardware and signed at manufacture time. This key will be static and never change for the life of the processor. Flow:

- Get the EK from the TPM and [retrieve the certificate from the key server](https://github.com/tpm2-software/tpm2-tools/issues/3158)
- Generate attestation key (AK)
- Send EK and AK to server
- Generate challenge on server
- Challenge the EK+AK to decrypt the challegne
- Verify the challenge output on the server

[reference this example](https://github.com/google/go-attestation/blob/f203ad309099f8efdef5f222d974fb8a2a8c1cd1/attest/example_test.go#L48)

### yubikey attestation

The webauthn flow with `attestation: "direct"` will return a signed attestation that proves the output signature comes from a real yubikey. This signed attestation contains a unique identifier of the device.

Most other hardware tokens do not support attestation or [do not expose unique information in the attestation certificate](https://docs.solokeys.dev/customization/):

> Attestation keys are typically the same for at least 100K units of a particular authenticator model. This is so they don't contribute a significant fingerprint that platforms could use to identify the user.

### iOS/macOS Profile Service

You can have iOS and macOS devices upload their signed device info to a server by installing a profile like this:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadContent</key>
        <dict>
            <key>URL</key>
            <string>https://test1234.requestcatcher.com/test</string>
            <key>DeviceAttributes</key>
            <array>
                <string>UDID</string>
                <string>IMEI</string>
                <string>ICCID</string>
                <string>VERSION</string>
                <string>PRODUCT</string>
            </array>
        </dict>
        <key>PayloadOrganization</key>
        <string>Example</string>
        <key>PayloadDisplayName</key>
        <string>Install to upload device identifiers to service</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadUUID</key>
        <string>c500198bd0a34f4aaf0fe97d7b25b559</string>
        <key>PayloadIdentifier</key>
        <string>com.random.c500198bd0a34f4aaf0fe97d7b25b559</string>
        <key>PayloadDescription</key>
        <string>Install to upload device identifiers to service</string>
        <key>PayloadType</key>
        <string>Profile Service</string>
    </dict>
</plist>
```

This will upload a DER encoded PKCS#7 file which contains signed data and a full certificate chain. If we restrict this to devices with secure enclaves, we should be relatively confident that this is trustworthy.

### Android?

You need to enroll a device in MDM to get it's IMEI. Probably not feasable.

## Wallet

### .01 mainnet eth

Request signature to prove account is owned.

### Patreon

With `identity.memberships` scope, you can see all memberships of a user including attributes like `lifetime_support_cents` and `will_pay_amount_cents`.
