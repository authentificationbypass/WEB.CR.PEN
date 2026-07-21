"""Tracker intelligence database.

Maps ~250 known tracking/advertising/analytics domains to a category and
human-readable name.  classify_tracker() checks exact matches first, then
falls back to suffix matching so subdomains are caught automatically.
"""
from __future__ import annotations

# Tracker database
# Keys are registrable base-domains.  Subdomains are caught by suffix matching.
TRACKER_DB: dict[str, dict[str, str]] = {

    # Analytics / Behavioural
    "google-analytics.com":         {"category": "analytics",    "name": "Google Analytics"},
    "analytics.google.com":         {"category": "analytics",    "name": "Google Analytics"},
    "googletagmanager.com":         {"category": "analytics",    "name": "Google Tag Manager"},
    "googletagservices.com":        {"category": "analytics",    "name": "Google Tag Services"},
    "hotjar.com":                   {"category": "analytics",    "name": "Hotjar"},
    "mixpanel.com":                 {"category": "analytics",    "name": "Mixpanel"},
    "cdn.mxpnl.com":                {"category": "analytics",    "name": "Mixpanel"},
    "segment.com":                  {"category": "analytics",    "name": "Segment"},
    "cdn.segment.com":              {"category": "analytics",    "name": "Segment"},
    "amplitude.com":                {"category": "analytics",    "name": "Amplitude"},
    "heapanalytics.com":            {"category": "analytics",    "name": "Heap Analytics"},
    "fullstory.com":                {"category": "analytics",    "name": "FullStory"},
    "mouseflow.com":                {"category": "analytics",    "name": "Mouseflow"},
    "clarity.ms":                   {"category": "analytics",    "name": "Microsoft Clarity"},
    "c.bing.com":                   {"category": "analytics",    "name": "Microsoft Bing/Clarity"},
    "crazyegg.com":                 {"category": "analytics",    "name": "Crazy Egg"},
    "kissmetrics.com":              {"category": "analytics",    "name": "Kissmetrics"},
    "piwik.pro":                    {"category": "analytics",    "name": "Piwik PRO"},
    "quantcast.com":                {"category": "analytics",    "name": "Quantcast"},
    "quantserve.com":               {"category": "analytics",    "name": "Quantserve"},
    "luckyorange.com":              {"category": "analytics",    "name": "Lucky Orange"},
    "logrocket.com":                {"category": "analytics",    "name": "LogRocket"},
    "cdn.logrocket.io":             {"category": "analytics",    "name": "LogRocket"},
    "inspectlet.com":               {"category": "analytics",    "name": "Inspectlet"},
    "chartbeat.com":                {"category": "analytics",    "name": "Chartbeat"},
    "woopra.com":                   {"category": "analytics",    "name": "Woopra"},
    "parsely.com":                  {"category": "analytics",    "name": "Parse.ly"},
    "newrelic.com":                 {"category": "analytics",    "name": "New Relic"},
    "nr-data.net":                  {"category": "analytics",    "name": "New Relic"},
    "datadoghq.com":                {"category": "analytics",    "name": "Datadog"},
    "plausible.io":                 {"category": "analytics",    "name": "Plausible Analytics"},
    "posthog.com":                  {"category": "analytics",    "name": "PostHog"},
    "clicky.com":                   {"category": "analytics",    "name": "Clicky"},
    "statcounter.com":              {"category": "analytics",    "name": "StatCounter"},
    "histats.com":                  {"category": "analytics",    "name": "Histats"},
    "matomo.cloud":                 {"category": "analytics",    "name": "Matomo Cloud"},
    "counter.dev":                  {"category": "analytics",    "name": "Counter.dev"},
    "clickio.com":                  {"category": "analytics",    "name": "Clickio"},
    "gauges.com":                   {"category": "analytics",    "name": "Gauges"},
    "heap.io":                      {"category": "analytics",    "name": "Heap.io"},

    # Advertising / Ad Networks
    "doubleclick.net":              {"category": "advertising",  "name": "Google DoubleClick"},
    "googleadservices.com":         {"category": "advertising",  "name": "Google Ads"},
    "googlesyndication.com":        {"category": "advertising",  "name": "Google AdSense"},
    "adservice.google.com":         {"category": "advertising",  "name": "Google Ad Service"},
    "2mdn.net":                     {"category": "advertising",  "name": "Google DoubleClick"},
    "criteo.com":                   {"category": "advertising",  "name": "Criteo"},
    "criteo.net":                   {"category": "advertising",  "name": "Criteo"},
    "adnxs.com":                    {"category": "advertising",  "name": "Xandr (AppNexus)"},
    "appnexus.com":                 {"category": "advertising",  "name": "Xandr (AppNexus)"},
    "rubiconproject.com":           {"category": "advertising",  "name": "Rubicon Project"},
    "pubmatic.com":                 {"category": "advertising",  "name": "PubMatic"},
    "openx.net":                    {"category": "advertising",  "name": "OpenX"},
    "openx.com":                    {"category": "advertising",  "name": "OpenX"},
    "taboola.com":                  {"category": "advertising",  "name": "Taboola"},
    "outbrain.com":                 {"category": "advertising",  "name": "Outbrain"},
    "media.net":                    {"category": "advertising",  "name": "Media.net"},
    "amazon-adsystem.com":          {"category": "advertising",  "name": "Amazon Advertising"},
    "adsrvr.org":                   {"category": "advertising",  "name": "The Trade Desk"},
    "casalemedia.com":              {"category": "advertising",  "name": "Index Exchange"},
    "indexww.com":                  {"category": "advertising",  "name": "Index Exchange"},
    "liveintent.com":               {"category": "advertising",  "name": "LiveIntent"},
    "bidswitch.net":                {"category": "advertising",  "name": "BidSwitch"},
    "advertising.com":              {"category": "advertising",  "name": "Yahoo Advertising"},
    "oath.com":                     {"category": "advertising",  "name": "Verizon / Oath"},
    "revcontent.com":               {"category": "advertising",  "name": "Revcontent"},
    "sharethrough.com":             {"category": "advertising",  "name": "Sharethrough"},
    "triplelift.com":               {"category": "advertising",  "name": "TripleLift"},
    "contextweb.com":               {"category": "advertising",  "name": "Pulsepoint"},
    "33across.com":                 {"category": "advertising",  "name": "33Across"},
    "smartadserver.com":            {"category": "advertising",  "name": "Smart AdServer"},
    "sovrn.com":                    {"category": "advertising",  "name": "Sovrn"},
    "lijit.com":                    {"category": "advertising",  "name": "Sovrn / Lijit"},
    "adform.net":                   {"category": "advertising",  "name": "Adform"},
    "adform.com":                   {"category": "advertising",  "name": "Adform"},
    "turn.com":                     {"category": "advertising",  "name": "Amobee"},
    "liveramp.com":                 {"category": "advertising",  "name": "LiveRamp"},
    "rlcdn.com":                    {"category": "advertising",  "name": "LiveRamp"},
    "addthis.com":                  {"category": "advertising",  "name": "AddThis (Oracle)"},
    "clearbit.com":                 {"category": "advertising",  "name": "Clearbit"},
    "bombora.com":                  {"category": "advertising",  "name": "Bombora"},
    "mopub.com":                    {"category": "advertising",  "name": "MoPub (X/Twitter)"},
    "smaato.com":                   {"category": "advertising",  "name": "Smaato"},
    "inmobi.com":                   {"category": "advertising",  "name": "InMobi"},
    "mobvista.com":                 {"category": "advertising",  "name": "Mobvista / Mintegral"},
    "mintegral.com":                {"category": "advertising",  "name": "Mintegral"},
    "yandex.ru":                    {"category": "advertising",  "name": "Yandex Advertising"},
    "an.yandex.ru":                 {"category": "advertising",  "name": "Yandex Advertising"},
    "mc.yandex.ru":                 {"category": "advertising",  "name": "Yandex Metrica"},
    "smartclip.net":                {"category": "advertising",  "name": "SmartClip"},
    "teads.tv":                     {"category": "advertising",  "name": "Teads"},
    "realmedia.com":                {"category": "advertising",  "name": "RealMedia (24/7)"},

    # Social Media Widgets / Pixels
    "connect.facebook.net":         {"category": "social",       "name": "Facebook Pixel / SDK"},
    "facebook.com":                 {"category": "social",       "name": "Facebook"},
    "fbcdn.net":                    {"category": "social",       "name": "Facebook CDN"},
    "platform.twitter.com":         {"category": "social",       "name": "Twitter / X Widget"},
    "analytics.twitter.com":        {"category": "social",       "name": "Twitter Analytics"},
    "static.ads-twitter.com":       {"category": "social",       "name": "Twitter Ads"},
    "t.co":                         {"category": "social",       "name": "Twitter Short Link"},
    "platform.linkedin.com":        {"category": "social",       "name": "LinkedIn Insight"},
    "snap.licdn.com":               {"category": "social",       "name": "LinkedIn Insight"},
    "ct.pinterest.com":             {"category": "social",       "name": "Pinterest Tag"},
    "analytics.tiktok.com":         {"category": "social",       "name": "TikTok Analytics"},
    "business-api.tiktok.com":      {"category": "social",       "name": "TikTok Business API"},
    "ads.tiktok.com":               {"category": "social",       "name": "TikTok Ads"},
    "sc-static.net":                {"category": "social",       "name": "Snapchat Pixel"},
    "tr.snapchat.com":              {"category": "social",       "name": "Snapchat Pixel"},
    "apis.google.com":              {"category": "social",       "name": "Google APIs"},
    "plus.google.com":              {"category": "social",       "name": "Google+"},
    "vk.com":                       {"category": "social",       "name": "VKontakte"},
    "userapi.com":                  {"category": "social",       "name": "VKontakte API"},
    "ok.ru":                        {"category": "social",       "name": "Odnoklassniki"},

    # Fingerprinting / Fraud Detection
    "fingerprintjs.com":            {"category": "fingerprinting","name": "FingerprintJS"},
    "fpnpmcdn.net":                 {"category": "fingerprinting","name": "FingerprintJS CDN"},
    "fingerprint.com":              {"category": "fingerprinting","name": "FingerprintJS Pro"},
    "threatmetrix.com":             {"category": "fingerprinting","name": "LexisNexis ThreatMetrix"},
    "online-metrix.net":            {"category": "fingerprinting","name": "ThreatMetrix"},
    "riskified.com":                {"category": "fingerprinting","name": "Riskified"},
    "signifyd.com":                 {"category": "fingerprinting","name": "Signifyd"},
    "ipqualityscore.com":           {"category": "fingerprinting","name": "IPQualityScore"},
    "seon.io":                      {"category": "fingerprinting","name": "SEON"},
    "maxmind.com":                  {"category": "fingerprinting","name": "MaxMind GeoIP"},
    "castle.io":                    {"category": "fingerprinting","name": "Castle"},
    "kount.com":                    {"category": "fingerprinting","name": "Kount"},
    "forter.com":                   {"category": "fingerprinting","name": "Forter"},
    "sardine.ai":                   {"category": "fingerprinting","name": "Sardine AI"},

    # CRM / Marketing Automation
    "hubspot.com":                  {"category": "crm",           "name": "HubSpot"},
    "hs-scripts.com":               {"category": "crm",           "name": "HubSpot"},
    "hs-analytics.net":             {"category": "crm",           "name": "HubSpot Analytics"},
    "hubapi.com":                   {"category": "crm",           "name": "HubSpot API"},
    "pardot.com":                   {"category": "crm",           "name": "Salesforce Pardot"},
    "marketo.net":                  {"category": "crm",           "name": "Adobe Marketo"},
    "mktoresp.com":                 {"category": "crm",           "name": "Adobe Marketo"},
    "intercom.io":                  {"category": "crm",           "name": "Intercom"},
    "intercom.com":                 {"category": "crm",           "name": "Intercom"},
    "klaviyo.com":                  {"category": "crm",           "name": "Klaviyo"},
    "mailchimp.com":                {"category": "crm",           "name": "Mailchimp"},
    "chimpstatic.com":              {"category": "crm",           "name": "Mailchimp"},
    "drift.com":                    {"category": "crm",           "name": "Drift"},
    "driftt.com":                   {"category": "crm",           "name": "Drift"},
    "freshmarketer.com":            {"category": "crm",           "name": "Freshmarketer"},
    "freshworks.com":               {"category": "crm",           "name": "Freshworks"},
    "zendesk.com":                  {"category": "crm",           "name": "Zendesk"},
    "zdassets.com":                 {"category": "crm",           "name": "Zendesk"},
    "crisp.chat":                   {"category": "crm",           "name": "Crisp Chat"},
    "tawk.to":                      {"category": "crm",           "name": "Tawk.to"},
    "livechat.com":                 {"category": "crm",           "name": "LiveChat"},
    "livechatinc.com":              {"category": "crm",           "name": "LiveChat"},
    "olark.com":                    {"category": "crm",           "name": "Olark"},
    "sendgrid.net":                 {"category": "crm",           "name": "SendGrid"},
    "braze.com":                    {"category": "crm",           "name": "Braze"},
    "customer.io":                  {"category": "crm",           "name": "Customer.io"},

    # A/B Testing / Experimentation
    "optimizely.com":               {"category": "ab_testing",    "name": "Optimizely"},
    "vwo.com":                      {"category": "ab_testing",    "name": "VWO"},
    "abtasty.com":                  {"category": "ab_testing",    "name": "AB Tasty"},
    "launchdarkly.com":             {"category": "ab_testing",    "name": "LaunchDarkly"},
    "split.io":                     {"category": "ab_testing",    "name": "Split.io"},
    "kameleoon.com":                {"category": "ab_testing",    "name": "Kameleoon"},
    "convert.com":                  {"category": "ab_testing",    "name": "Convert"},
    "growthbook.io":                {"category": "ab_testing",    "name": "GrowthBook"},

    # Data Brokers / DMPs
    "bluekai.com":                  {"category": "data_broker",   "name": "Oracle BlueKai"},
    "bkrtx.com":                    {"category": "data_broker",   "name": "Oracle BlueKai"},
    "acxiom.com":                   {"category": "data_broker",   "name": "Acxiom"},
    "datalogix.com":                {"category": "data_broker",   "name": "Oracle Datalogix"},
    "lotame.com":                   {"category": "data_broker",   "name": "Lotame"},
    "crwdcntrl.net":                {"category": "data_broker",   "name": "Lotame"},
    "krxd.net":                     {"category": "data_broker",   "name": "Salesforce Krux"},
    "exelate.com":                  {"category": "data_broker",   "name": "Nielsen eXelate"},
    "scorecardresearch.com":        {"category": "data_broker",   "name": "comScore"},
    "demdex.net":                   {"category": "data_broker",   "name": "Adobe Audience Manager"},
    "omtrdc.net":                   {"category": "data_broker",   "name": "Adobe Analytics"},
    "adobedtm.com":                 {"category": "data_broker",   "name": "Adobe DTM"},
    "everesttech.net":              {"category": "data_broker",   "name": "Adobe Advertising Cloud"},
    "zemanta.com":                  {"category": "data_broker",   "name": "Zemanta (Outbrain)"},
    "neustar.biz":                  {"category": "data_broker",   "name": "Neustar"},
    "nielsen.com":                  {"category": "data_broker",   "name": "Nielsen"},
    "comscore.com":                 {"category": "data_broker",   "name": "comScore"},
}

# Category metadata
CATEGORY_META: dict[str, dict[str, str]] = {
    "analytics":     {"label": "Analytics",      "color": "blue"},
    "advertising":   {"label": "Advertising",    "color": "orange"},
    "social":        {"label": "Social",         "color": "purple"},
    "fingerprinting":{"label": "Fingerprinting", "color": "red"},
    "crm":           {"label": "CRM / Chat",     "color": "teal"},
    "ab_testing":    {"label": "A/B Testing",    "color": "yellow"},
    "data_broker":   {"label": "Data Broker",    "color": "pink"},
}


def classify_tracker(domain: str) -> dict[str, str] | None:
    """Return tracker info dict (category, name) if the domain is a known tracker, else None."""
    domain = domain.lower().strip()
    if not domain:
        return None

    # 1. Exact match
    if domain in TRACKER_DB:
        return TRACKER_DB[domain]

    # 2. Suffix match — catches subdomains like "cdn.amplitude.com" → "amplitude.com"
    for base, info in TRACKER_DB.items():
        if domain.endswith("." + base):
            return info

    return None
