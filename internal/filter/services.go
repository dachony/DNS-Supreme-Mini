package filter

import (
	"log/slog"
	"strings"
	"sync"
)

// ServiceCategory groups related services
type ServiceCategory struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Icon     string    `json:"icon"`
	Services []Service `json:"services"`
}

// Service represents a blockable online service
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Logo    string   `json:"logo"`
	Domains []string `json:"domains"`
	Enabled bool     `json:"enabled"`
}

// ServiceBlocker manages service-level domain blocking
type ServiceBlocker struct {
	mu              sync.RWMutex
	enabledServices map[string]bool   // service ID -> enabled
	serviceDomains  map[string]string // domain -> service ID (for fast lookup)
	categories      []ServiceCategory
}

func NewServiceBlocker() *ServiceBlocker {
	sb := &ServiceBlocker{
		enabledServices: make(map[string]bool),
		serviceDomains:  make(map[string]string),
		categories:      defaultServiceCategories(),
	}
	sb.rebuildDomainIndex()
	return sb
}

// Check returns whether a domain is blocked by a service block rule
func (sb *ServiceBlocker) Check(domain string) (blocked bool, rule string) {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	// Check exact match and parent domains
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		checkDomain := strings.Join(parts[i:], ".")
		if svcID, ok := sb.serviceDomains[checkDomain]; ok {
			if sb.enabledServices[svcID] {
				return true, "service:" + svcID
			}
		}
	}
	return false, ""
}

// SetServiceEnabled enables or disables blocking for a service
func (sb *ServiceBlocker) SetServiceEnabled(serviceID string, enabled bool) {
	sb.mu.Lock()
	if enabled {
		sb.enabledServices[serviceID] = true
	} else {
		delete(sb.enabledServices, serviceID)
	}
	sb.mu.Unlock()
	slog.Info("service block toggled", "component", "services", "service", serviceID, "enabled", enabled)
}

// SetCategoryEnabled enables or disables all services in a category
func (sb *ServiceBlocker) SetCategoryEnabled(categoryID string, enabled bool) {
	sb.mu.Lock()
	for _, cat := range sb.categories {
		if cat.ID == categoryID {
			for _, svc := range cat.Services {
				if enabled {
					sb.enabledServices[svc.ID] = true
				} else {
					delete(sb.enabledServices, svc.ID)
				}
			}
			break
		}
	}
	sb.mu.Unlock()
	slog.Info("service category toggled", "component", "services", "category", categoryID, "enabled", enabled)
}

// GetCategories returns all service categories with current enabled state
func (sb *ServiceBlocker) GetCategories() []ServiceCategory {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	result := make([]ServiceCategory, len(sb.categories))
	for i, cat := range sb.categories {
		catCopy := ServiceCategory{
			ID:       cat.ID,
			Name:     cat.Name,
			Icon:     cat.Icon,
			Services: make([]Service, len(cat.Services)),
		}
		for j, svc := range cat.Services {
			catCopy.Services[j] = Service{
				ID:      svc.ID,
				Name:    svc.Name,
				Logo:    svc.Logo,
				Domains: svc.Domains,
				Enabled: sb.enabledServices[svc.ID],
			}
		}
		result[i] = catCopy
	}
	return result
}

// GetEnabledServiceIDs returns list of enabled service IDs for persistence
func (sb *ServiceBlocker) GetEnabledServiceIDs() []string {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	ids := make([]string, 0, len(sb.enabledServices))
	for id := range sb.enabledServices {
		ids = append(ids, id)
	}
	return ids
}

// RestoreEnabled restores enabled services from persisted IDs
func (sb *ServiceBlocker) RestoreEnabled(ids []string) {
	sb.mu.Lock()
	for _, id := range ids {
		sb.enabledServices[id] = true
	}
	sb.mu.Unlock()
	slog.Info("restored blocked services", "component", "services", "count", len(ids))
}

func (sb *ServiceBlocker) rebuildDomainIndex() {
	sb.serviceDomains = make(map[string]string)
	for _, cat := range sb.categories {
		for _, svc := range cat.Services {
			for _, domain := range svc.Domains {
				sb.serviceDomains[strings.ToLower(domain)] = svc.ID
			}
		}
	}
}

func defaultServiceCategories() []ServiceCategory {
	return []ServiceCategory{
		{
			ID: "ai", Name: "AI Services", Icon: "AI",
			Services: []Service{
				{ID: "chatgpt", Name: "ChatGPT", Logo: "chatgpt", Domains: []string{
					"chat.openai.com", "chatgpt.com", "api.openai.com", "openai.com",
					"auth0.openai.com", "platform.openai.com",
				}},
				{ID: "claude", Name: "Claude", Logo: "claude", Domains: []string{
					"claude.ai", "api.anthropic.com", "anthropic.com",
				}},
				{ID: "gemini", Name: "Gemini", Logo: "gemini", Domains: []string{
					"gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com",
					"alkalimakersuite-pa.clients6.google.com",
				}},
				{ID: "deepseek", Name: "DeepSeek", Logo: "deepseek", Domains: []string{
					"deepseek.com", "chat.deepseek.com", "api.deepseek.com",
				}},
				{ID: "copilot", Name: "Microsoft Copilot", Logo: "copilot", Domains: []string{
					"copilot.microsoft.com", "sydney.bing.com", "edgeservices.bing.com",
					"copilot.cloud.microsoft",
				}},
				{ID: "perplexity", Name: "Perplexity", Logo: "perplexity", Domains: []string{
					"perplexity.ai", "www.perplexity.ai", "api.perplexity.ai",
				}},
				{ID: "midjourney", Name: "Midjourney", Logo: "midjourney", Domains: []string{
					"midjourney.com", "www.midjourney.com",
				}},
				{ID: "grok", Name: "Grok", Logo: "grok", Domains: []string{
					"grok.x.ai", "x.ai", "api.x.ai",
				}},
				{ID: "huggingface", Name: "Hugging Face", Logo: "huggingface", Domains: []string{
					"huggingface.co", "api-inference.huggingface.co",
				}},
			},
		},
		{
			ID: "social", Name: "Social Media", Icon: "SC",
			Services: []Service{
				{ID: "facebook", Name: "Facebook", Logo: "facebook", Domains: []string{
					"facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com",
					"fbcdn.net", "fbsbx.com", "facebook.net", "fb.com", "fb.me",
					"connect.facebook.net", "graph.facebook.com", "static.xx.fbcdn.net",
				}},
				{ID: "instagram", Name: "Instagram", Logo: "instagram", Domains: []string{
					"instagram.com", "www.instagram.com", "i.instagram.com",
					"cdninstagram.com", "scontent.cdninstagram.com",
				}},
				{ID: "tiktok", Name: "TikTok", Logo: "tiktok", Domains: []string{
					"tiktok.com", "www.tiktok.com", "m.tiktok.com", "vm.tiktok.com",
					"tiktokcdn.com", "tiktokv.com", "musical.ly",
					"p16-sign-sg.tiktokcdn.com", "sf16-website-login.neutral.ttwstatic.com",
				}},
				{ID: "twitter", Name: "X / Twitter", Logo: "twitter", Domains: []string{
					"twitter.com", "x.com", "t.co", "twimg.com", "api.twitter.com",
					"abs.twimg.com", "pbs.twimg.com", "mobile.twitter.com",
				}},
				{ID: "snapchat", Name: "Snapchat", Logo: "snapchat", Domains: []string{
					"snapchat.com", "www.snapchat.com", "app.snapchat.com",
					"sc-cdn.net", "snap.com", "snapkit.co",
				}},
				{ID: "linkedin", Name: "LinkedIn", Logo: "linkedin", Domains: []string{
					"linkedin.com", "www.linkedin.com", "static.licdn.com",
					"media.licdn.com", "platform.linkedin.com",
				}},
				{ID: "reddit", Name: "Reddit", Logo: "reddit", Domains: []string{
					"reddit.com", "www.reddit.com", "old.reddit.com",
					"redd.it", "i.redd.it", "v.redd.it", "preview.redd.it",
					"external-preview.redd.it", "redditstatic.com",
				}},
				{ID: "pinterest", Name: "Pinterest", Logo: "pinterest", Domains: []string{
					"pinterest.com", "www.pinterest.com", "pinimg.com",
					"i.pinimg.com", "api.pinterest.com",
				}},
				{ID: "threads", Name: "Threads", Logo: "threads", Domains: []string{
					"threads.net", "www.threads.net",
				}},
			},
		},
		{
			ID: "video", Name: "Video Streaming", Icon: "VD",
			Services: []Service{
				{ID: "youtube", Name: "YouTube", Logo: "youtube", Domains: []string{
					"youtube.com", "www.youtube.com", "m.youtube.com",
					"youtubei.googleapis.com", "yt3.ggpht.com",
					"googlevideo.com", "youtu.be", "youtube-nocookie.com",
					"youtube-ui.l.google.com",
				}},
				{ID: "netflix", Name: "Netflix", Logo: "netflix", Domains: []string{
					"netflix.com", "www.netflix.com", "api-global.netflix.com",
					"nflximg.net", "nflxvideo.net", "nflxso.net", "nflxext.com",
				}},
				{ID: "twitch", Name: "Twitch", Logo: "twitch", Domains: []string{
					"twitch.tv", "www.twitch.tv", "m.twitch.tv",
					"static.twitchcdn.net", "jtvnw.net", "ttvnw.net",
					"clips.twitch.tv", "api.twitch.tv",
				}},
				{ID: "disneyplus", Name: "Disney+", Logo: "disneyplus", Domains: []string{
					"disneyplus.com", "www.disneyplus.com",
					"disney-plus.net", "dssott.com", "bamgrid.com",
					"disney.api.edge.bamgrid.com", "registerdisney.go.com",
				}},
				{ID: "hbomax", Name: "HBO Max", Logo: "hbomax", Domains: []string{
					"hbomax.com", "www.hbomax.com", "max.com", "play.max.com",
					"defaultcdn.wbd.com", "wbd.com",
				}},
				{ID: "primevideo", Name: "Prime Video", Logo: "primevideo", Domains: []string{
					"primevideo.com", "www.primevideo.com",
					"atv-ps.amazon.com", "aiv-cdn.net", "aiv-delivery.net",
					"dmqdd6hw24ucf.cloudfront.net",
				}},
			},
		},
		{
			ID: "audio", Name: "Audio Streaming", Icon: "AU",
			Services: []Service{
				{ID: "spotify", Name: "Spotify", Logo: "spotify", Domains: []string{
					"spotify.com", "open.spotify.com", "api.spotify.com",
					"scdn.co", "i.scdn.co", "audio-ak-spotify-com.akamaized.net",
					"dealer.spotify.com", "apresolve.spotify.com",
				}},
				{ID: "applemusic", Name: "Apple Music", Logo: "applemusic", Domains: []string{
					"music.apple.com", "itunes.apple.com",
					"is1-ssl.mzstatic.com", "play.itunes.apple.com",
					"amp-api.music.apple.com",
				}},
				{ID: "deezer", Name: "Deezer", Logo: "deezer", Domains: []string{
					"deezer.com", "www.deezer.com", "api.deezer.com",
					"e-cdns-images.dzcdn.net", "cdns-preview-d.dzcdn.net",
				}},
				{ID: "soundcloud", Name: "SoundCloud", Logo: "soundcloud", Domains: []string{
					"soundcloud.com", "api.soundcloud.com", "api-v2.soundcloud.com",
					"sndcdn.com", "i1.sndcdn.com",
				}},
				{ID: "tidal", Name: "Tidal", Logo: "tidal", Domains: []string{
					"tidal.com", "listen.tidal.com", "api.tidal.com",
					"resources.tidal.com",
				}},
			},
		},
		{
			ID: "messaging", Name: "Messaging", Icon: "MS",
			Services: []Service{
				{ID: "whatsapp", Name: "WhatsApp", Logo: "whatsapp", Domains: []string{
					"whatsapp.com", "web.whatsapp.com", "www.whatsapp.com",
					"whatsapp.net", "wa.me",
					"static.whatsapp.net", "mmg.whatsapp.net",
				}},
				{ID: "telegram", Name: "Telegram", Logo: "telegram", Domains: []string{
					"telegram.org", "web.telegram.org", "t.me",
					"core.telegram.org", "telegram.me",
				}},
				{ID: "discord", Name: "Discord", Logo: "discord", Domains: []string{
					"discord.com", "www.discord.com", "discordapp.com",
					"cdn.discordapp.com", "gateway.discord.gg",
					"discord.gg", "media.discordapp.net",
				}},
				{ID: "signal", Name: "Signal", Logo: "signal", Domains: []string{
					"signal.org", "www.signal.org",
					"chat.signal.org", "storage.signal.org",
					"cdn.signal.org", "cdn2.signal.org",
				}},
				{ID: "viber", Name: "Viber", Logo: "viber", Domains: []string{
					"viber.com", "www.viber.com",
					"dl-media.viber.com", "share.viber.com",
				}},
			},
		},
		{
			ID: "gaming", Name: "Gaming", Icon: "GM",
			Services: []Service{
				{ID: "steam", Name: "Steam", Logo: "steam", Domains: []string{
					"store.steampowered.com", "steampowered.com", "steamcommunity.com",
					"steamstatic.com", "steamcdn-a.akamaihd.net",
					"api.steampowered.com", "steam.com",
				}},
				{ID: "epicgames", Name: "Epic Games", Logo: "epicgames", Domains: []string{
					"epicgames.com", "www.epicgames.com", "store.epicgames.com",
					"launcher-public-service-prod06.ol.epicgames.com",
					"download.epicgames.com",
				}},
				{ID: "roblox", Name: "Roblox", Logo: "roblox", Domains: []string{
					"roblox.com", "www.roblox.com", "web.roblox.com",
					"rbxcdn.com", "roblox.qq.com",
					"apis.roblox.com", "auth.roblox.com",
				}},
				{ID: "xboxlive", Name: "Xbox Live", Logo: "xboxlive", Domains: []string{
					"xbox.com", "www.xbox.com", "xboxlive.com",
					"xbl.io", "user.auth.xboxlive.com",
					"login.live.com",
				}},
				{ID: "playstation", Name: "PlayStation", Logo: "playstation", Domains: []string{
					"playstation.com", "www.playstation.com", "store.playstation.com",
					"playstation.net", "sonyentertainmentnetwork.com",
					"auth.api.sonyentertainmentnetwork.com",
				}},
			},
		},
	}
}
