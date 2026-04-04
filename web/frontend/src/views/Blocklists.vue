<template>
  <div class="blocklists">
    <h2>DNS Filtering</h2>

    <!-- Tabs -->
    <div class="tabs">
      <button v-for="t in tabs" :key="t.id" :class="{ active: activeTab === t.id }" @click="activeTab = t.id" class="tab-btn">{{ t.label }}</button>
    </div>

    <!-- TAB: Services -->
    <div v-if="activeTab === 'services'" class="tab-content">
      <div class="services-layout">
        <div class="services-left">
          <div class="services-section">
            <h3>Filtering Categories</h3>
            <p class="section-desc">Enable or disable domain blocking categories.</p>
            <div class="svc-list">
              <div v-for="cat in categories" :key="cat.name" class="svc-item" :class="{ disabled: !cat.enabled }" @click="isAdmin && toggleCategory(cat)" :style="!isAdmin ? 'cursor: default' : ''">
                <span class="svc-icon">{{ categoryIcon(cat.name) }}</span>
                <div class="svc-info">
                  <span class="svc-name">{{ cat.name }}</span>
                  <span class="svc-count">{{ cat.domains?.toLocaleString() || 0 }} domains</span>
                </div>
                <div class="toggle" :class="{ on: cat.enabled, disabled: !isAdmin }"><div class="toggle-knob"></div></div>
              </div>
            </div>
          </div>

          <div class="services-section">
            <h3>Network Protection</h3>
            <div class="svc-item master" :class="{ disabled: !npEnabled }" @click="isAdmin && toggleNpMaster()" :style="!isAdmin ? 'cursor: default' : ''">
              <span class="svc-icon svc-icon-np">NP</span>
              <div class="svc-info">
                <span class="svc-name">Network Protection</span>
                <span class="svc-count">Tor, botnets, malicious IPs, Spamhaus, URLhaus</span>
              </div>
              <div class="toggle" :class="{ on: npEnabled, disabled: !isAdmin }"><div class="toggle-knob"></div></div>
            </div>
          </div>

          <div class="services-section">
            <h3>Block Services</h3>
            <p class="section-desc">Block popular platforms by category.</p>
            <div class="svc-item master" :class="{ disabled: bsTotalBlocked === 0 }" @click="activeTab = 'block-services'">
              <span class="svc-icon svc-icon-bs">BS</span>
              <div class="svc-info">
                <span class="svc-name">Service Blocking</span>
                <span class="svc-count">{{ bsTotalBlocked > 0 ? bsTotalBlocked + ' services blocked (' + bsTotalDomains + ' domains)' : 'No services blocked' }}</span>
              </div>
              <div class="toggle" :class="{ on: bsTotalBlocked > 0 }"><div class="toggle-knob"></div></div>
            </div>
            <div class="svc-bs-cats" v-if="blockServiceCategories.length">
              <div v-for="cat in blockServiceCategories" :key="cat.id" class="svc-bs-cat" :class="{ active: bsCatEnabledCount(cat) > 0 }">
                <span class="svc-bs-cat-icon" :class="'bs-cat-icon-' + cat.id">{{ cat.icon }}</span>
                <span class="svc-bs-cat-name">{{ cat.name }}</span>
                <span class="svc-bs-cat-count">{{ bsCatEnabledCount(cat) }}/{{ cat.services.length }}</span>
              </div>
            </div>
          </div>

          <div class="services-section">
            <h3>Network Protection</h3>
            <div class="svc-item master" :class="{ disabled: !npEnabled }" @click="isAdmin && toggleNpMaster()" :style="!isAdmin ? 'cursor: default' : ''">
              <span class="svc-icon svc-icon-np">NP</span>
              <div class="svc-info">
                <span class="svc-name">Network Protection</span>
                <span class="svc-count">Tor, botnets, malicious IPs, Spamhaus, URLhaus</span>
              </div>
              <div class="toggle" :class="{ on: npEnabled, disabled: !isAdmin }"><div class="toggle-knob"></div></div>
            </div>
          </div>

          <div class="services-section">
            <h3>Country Blocking</h3>
            <div class="svc-item master" :class="{ disabled: !geoEnabled }" @click="activeTab = 'netprotect'">
              <span class="svc-icon svc-icon-geo">GEO</span>
              <div class="svc-info">
                <span class="svc-name">Country Blocking</span>
                <span class="svc-count">{{ geoBlocked.length ? geoBlocked.length + ' countries blocked' : 'No countries blocked' }}</span>
              </div>
              <div class="toggle" :class="{ on: geoEnabled }"><div class="toggle-knob"></div></div>
            </div>
          </div>
        </div>

        <div class="services-right">
          <div class="services-section">
            <h3>How Filtering Works</h3>
            <p class="section-desc">Rules are evaluated in order. First match wins.</p>
            <div class="priority-chain compact">
              <div class="priority-step" v-for="s in prioritySteps" :key="s.num">
                <span class="priority-num" :class="{ pass: s.pass }">{{ s.pass ? '\u2713' : s.num }}</span>
                <div class="priority-info">
                  <span class="priority-title">{{ s.title }}</span>
                </div>
                <span class="priority-result" :class="s.result">{{ s.result.toUpperCase() }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: Active Lists -->
    <div v-if="activeTab === 'lists'" class="tab-content">
      <div class="al-toolbar" v-if="isAdmin">
        <div class="add-form" style="flex:1;margin-bottom:0">
          <input v-model="newName" placeholder="List name..." />
          <input v-model="newUrl" placeholder="URL (hosts file, domain list, GitHub raw)..." class="url-input" />
          <select v-model="newCategory">
            <option value="ads">Ads</option><option value="malware">Malware</option>
            <option value="adult">Adult</option><option value="social">Social</option>
            <option value="gambling">Gambling</option><option value="tracking">Tracking</option>
            <option value="uncategorized">Other</option>
          </select>
          <button @click="addList" :disabled="!newName || !newUrl" class="btn-add">Add List</button>
        </div>
        <div class="al-actions">
          <button @click="deleteAllLists" :disabled="!lists.length" class="btn-delete-all">Delete All</button>
        </div>
      </div>
      <div v-if="addError" class="error-msg">{{ addError }}</div>

      <!-- Filters + Schedule row -->
      <div class="al-filters-row" v-if="lists.length">
        <div class="catalog-filters">
          <button v-for="cat in activeListCategories" :key="cat"
            :class="{ active: activeListFilter === cat }" @click="activeListFilter = activeListFilter === cat ? '' : cat"
            class="catalog-filter-btn">{{ cat }} <span class="filter-count">{{ activeListCategoryCounts[cat] || 0 }}</span></button>
        </div>
        <div class="al-schedule-inline" v-if="isAdmin">
          <button @click="updateAllLists" :disabled="updatingLists" class="btn-update-now">
            {{ updatingLists ? 'Updating...' : 'Update Now' }}
          </button>
          <select v-model="updateInterval" @change="saveUpdateInterval" class="schedule-select">
            <option value="0">Auto-update: Off</option>
            <option value="1">Every hour</option>
            <option value="6">Every 6 hours</option>
            <option value="12">Every 12 hours</option>
            <option value="24">Every 24 hours</option>
            <option value="48">Every 48 hours</option>
            <option value="168">Weekly</option>
          </select>
        </div>
      </div>

      <div class="al-list">
        <div v-for="list in filteredActiveLists" :key="list.name" class="al-row" @click="openListDetail(list)">
          <span class="list-cat-badge" :class="list.category">{{ list.category }}</span>
          <div class="al-row-info">
            <span class="al-row-name">{{ list.name }}</span>
            <span class="al-row-url">{{ list.url }}</span>
          </div>
          <span class="al-row-count">{{ list.count?.toLocaleString() }} domains</span>
          <button v-if="isAdmin" @click.stop="removeList(list.name)" class="btn-delete-row" title="Delete">Delete</button>
        </div>
        <div v-if="!lists.length" class="empty">No blocklists configured — add one above or browse the Community Blocklists tab.</div>
        <div v-else-if="!filteredActiveLists.length" class="empty">No lists match the selected category.</div>
      </div>

      <!-- Active Blocked Services -->
      <div v-if="activeBlockedServices.length" class="al-section">
        <h4 class="al-section-title">Blocked Services</h4>
        <div class="al-list">
          <div v-for="svc in activeBlockedServices" :key="svc.id" class="al-row al-row-svc" @click="activeTab = 'block-services'">
            <span class="list-cat-badge service">service</span>
            <div class="al-row-info">
              <span class="al-row-name">{{ svc.name }}</span>
              <span class="al-row-url">{{ svc.category }}</span>
            </div>
            <span class="al-row-count">{{ svc.domains.length }} domains</span>
          </div>
        </div>
      </div>

      <div class="stats-bar" v-if="totalDomains > 0 || activeBlockedServices.length">
        Total: {{ (totalDomains + activeServiceDomains).toLocaleString() }} domains across {{ totalLists }} lists{{ activeBlockedServices.length ? ' + ' + activeBlockedServices.length + ' services' : '' }}
      </div>

      <!-- List detail modal -->
      <div v-if="listDetail" class="modal-overlay" @click.self="listDetail = null">
        <div class="modal-detail">
          <div class="modal-header">
            <div>
              <h3>{{ listDetail.name }}</h3>
              <span class="list-cat-badge" :class="listDetail.category" style="margin-top:4px;display:inline-block">{{ listDetail.category }}</span>
            </div>
            <button @click="listDetail = null" class="modal-close">&times;</button>
          </div>
          <div class="ld-meta">
            <span>{{ listDetail.count?.toLocaleString() }} domains total</span>
            <span class="ld-url">{{ listDetail.url }}</span>
          </div>
          <div v-if="listDetailLoading" class="ld-loading">Loading sample...</div>
          <div v-else-if="listDetailDomains.length" class="ld-domains">
            <div class="ld-domains-header">
              <span>Sample ({{ listDetailDomains.length }} of {{ listDetail.count?.toLocaleString() }})</span>
              <input v-model="listDetailSearch" placeholder="Filter domains..." class="ld-search" />
            </div>
            <div class="ld-domain-list">
              <div v-for="d in filteredDetailDomains" :key="d" class="ld-domain">{{ d }}</div>
              <div v-if="!filteredDetailDomains.length" class="empty-small">No domains match filter</div>
            </div>
          </div>
          <div v-else class="empty-small">No domain data available</div>
        </div>
      </div>
    </div>

    <!-- TAB: Block Services -->
    <div v-if="activeTab === 'block-services'" class="tab-content">
      <div class="bs-layout">
        <div class="bs-col" v-for="colIdx in 3" :key="colIdx">
          <div v-for="cat in bsColumned[colIdx - 1]" :key="cat.id" class="bs-category">
            <div class="bs-cat-header">
              <div class="bs-cat-left">
                <span class="bs-cat-icon" :class="'bs-cat-icon-' + cat.id">{{ cat.icon }}</span>
                <div class="bs-cat-info">
                  <span class="bs-cat-name">{{ cat.name }}</span>
                  <span class="bs-cat-count">{{ bsCatEnabledCount(cat) }} / {{ cat.services.length }} blocked</span>
                </div>
              </div>
              <div class="toggle" :class="{ on: bsCatAllEnabled(cat), partial: bsCatPartial(cat), disabled: !isAdmin }"
                @click="isAdmin && toggleBsCategory(cat)">
                <div class="toggle-knob"></div>
              </div>
            </div>
            <div class="bs-services">
              <div v-for="svc in cat.services" :key="svc.id" class="bs-service" :class="{ blocked: svc.enabled }"
                @click="isAdmin && toggleBsService(svc)" :style="!isAdmin ? 'cursor: default' : ''">
                <div class="bs-svc-logo" :class="'bs-logo-' + svc.logo">{{ svcInitials(svc.name) }}</div>
                <div class="bs-svc-info">
                  <span class="bs-svc-name">{{ svc.name }}</span>
                  <span class="bs-svc-domains">{{ svc.domains.length }} domains</span>
                </div>
                <div class="toggle small" :class="{ on: svc.enabled, disabled: !isAdmin }">
                  <div class="toggle-knob"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: Community Blocklists -->
    <div v-if="activeTab === 'community'" class="tab-content">
      <div class="community-toolbar">
        <div class="catalog-search" style="flex:1;margin-bottom:0">
          <input v-model="catalogSearch" placeholder="Search lists..." />
          <div class="catalog-filters">
            <button v-for="cat in catalogCategories" :key="cat"
              :class="{ active: catalogFilter === cat }" @click="catalogFilter = catalogFilter === cat ? '' : cat"
              class="catalog-filter-btn">{{ cat }}</button>
          </div>
        </div>
        <div class="community-actions" v-if="isAdmin">
          <span v-if="newCatalogCount > 0" class="new-count-badge">{{ newCatalogCount }} available</span>
          <button @click="checkForUpdates" :disabled="catalogAdding === 'checking'" class="btn-check-updates">
            {{ catalogAdding === 'checking' ? 'Checking...' : 'Check for Updates' }}
          </button>
        </div>
      </div>
      <div v-for="provider in filteredCatalog" :key="provider.name" class="catalog-provider">
        <div class="provider-header">
          <div class="provider-info">
            <span class="provider-name">{{ provider.name }}</span>
            <span class="provider-desc">{{ provider.description }}</span>
          </div>
          <a :href="provider.github" target="_blank" rel="noopener" class="provider-link">GitHub</a>
        </div>
        <div class="catalog-lists">
          <div v-for="item in provider.lists" :key="item.name" class="catalog-item" :class="{ added: isListAdded(item.name) }">
            <div class="catalog-item-info">
              <div class="catalog-item-header">
                <span class="catalog-item-name">{{ item.name }}</span>
                <span class="list-cat-badge" :class="item.category">{{ item.category }}</span>
                <span v-if="item.entries" class="catalog-item-size">~{{ item.entries }}</span>
              </div>
              <span class="catalog-item-desc">{{ item.description }}</span>
            </div>
            <button v-if="isAdmin && !isListAdded(item.name)" @click="addFromCatalog(item)" :disabled="catalogAdding === item.name" class="btn-catalog-add">
              {{ catalogAdding === item.name ? 'Adding...' : 'Add' }}
            </button>
            <span v-else class="catalog-added-badge">Added</span>
          </div>
        </div>
      </div>
      <div v-if="!filteredCatalog.length" class="empty">No lists match your search</div>
    </div>

    <!-- TAB: Premium Feeds -->
    <div v-if="activeTab === 'premium'" class="tab-content">
      <p class="section-desc">Connect premium and enterprise data feeds. These feeds are categorized as malware/threat intelligence by default.</p>
      <div class="ti-providers">
        <div v-for="ti in tiFeedProviders" :key="ti.name" class="ti-card">
          <div class="ti-card-header">
            <span class="ti-card-name">{{ ti.name }}</span>
            <span class="ti-card-type">{{ ti.type }}</span>
          </div>
          <p class="ti-card-desc">{{ ti.description }}</p>
          <div class="ti-card-formats" v-if="ti.formats">
            <span class="ti-format" v-for="f in ti.formats" :key="f">{{ f }}</span>
          </div>
          <div class="ti-add-form" v-if="isAdmin">
            <input v-model="tiFeedUrls[ti.id]" :placeholder="ti.placeholder" />
            <input v-model="tiFeedApiKeys[ti.id]" placeholder="API key (if required)" class="ti-apikey-input" />
            <button @click="addTiFeed(ti)" :disabled="!tiFeedUrls[ti.id]" class="btn-catalog-add">Add Feed</button>
          </div>
          <a v-if="ti.website" :href="ti.website" target="_blank" rel="noopener" class="ti-website">{{ ti.websiteLabel }}</a>
        </div>
      </div>
    </div>

    <!-- TAB: Custom Feeds -->
    <div v-if="activeTab === 'custom'" class="tab-content">
      <p class="section-desc">Add any blocklist or threat feed by URL. Supports hosts files, domain lists, and AdBlock filter lists.</p>
      <div v-if="isAdmin" class="ti-card ti-card-custom" style="margin-bottom: 16px">
        <div class="ti-card-header">
          <span class="ti-card-name">Add Custom Feed</span>
        </div>
        <div class="ti-add-form">
          <input v-model="customFeedName" placeholder="Feed name (e.g. Fortinet IOC Daily)" />
          <input v-model="customFeedUrl" placeholder="https://..." class="ti-url-input" />
          <select v-model="customFeedCategory">
            <option value="malware">Malware</option><option value="ads">Ads</option>
            <option value="tracking">Tracking</option><option value="adult">Adult</option>
            <option value="uncategorized">Other</option>
          </select>
          <button @click="addCustomFeed" :disabled="!customFeedName || !customFeedUrl" class="btn-catalog-add">Add</button>
        </div>
      </div>
      <div v-if="addError" class="error-msg">{{ addError }}</div>
    </div>

    <!-- TAB: Rules & Policies -->
    <div v-if="activeTab === 'rules'" class="tab-content">
      <div class="rules-grid">
        <div class="rules-col">
          <h3 class="rules-title allow-title">Global Allowlist</h3>
          <p class="section-desc">Always allowed — overrides all blocklists.</p>
          <div v-if="isAdmin" class="add-form compact">
            <input v-model="allowDomain" placeholder="Domain to allow..." />
            <button @click="addAllow" :disabled="!allowDomain" class="btn-add allow">Allow</button>
          </div>
          <div class="lists">
            <div v-for="domain in allowlist" :key="domain" class="list-item">
              <span class="list-name">{{ domain }}</span>
              <button v-if="isAdmin" @click="removeAllow(domain)" class="btn-remove">Remove</button>
            </div>
            <div v-if="!allowlist.length" class="empty-small">No entries</div>
          </div>
        </div>
        <div class="rules-col">
          <h3 class="rules-title block-title">Custom Block Rules</h3>
          <p class="section-desc">Manually blocked domains.</p>
          <div v-if="isAdmin" class="add-form compact">
            <input v-model="customDomain" placeholder="Domain to block..." />
            <input v-model="customReason" placeholder="Reason..." />
            <button @click="addCustom" :disabled="!customDomain" class="btn-add">Block</button>
          </div>
          <div class="lists">
            <div v-for="(reason, domain) in customBlocks" :key="domain" class="list-item">
              <div class="list-info">
                <span class="list-name">{{ domain }}</span>
                <span class="list-url" v-if="reason">{{ reason }}</span>
              </div>
              <button v-if="isAdmin" @click="removeCustom(domain as string)" class="btn-remove">Unblock</button>
            </div>
            <div v-if="!Object.keys(customBlocks).length" class="empty-small">No custom blocks</div>
          </div>
        </div>
        <div class="rules-col wide">
          <h3 class="rules-title policy-title">Per-Device Policies</h3>
          <p class="section-desc">Override rules for specific devices by IP.</p>
          <div v-if="isAdmin" class="add-form compact">
            <input v-model="newPolicy.client_ip" placeholder="Device IP..." />
            <input v-model="newPolicy.name" placeholder="Name..." />
            <button @click="addPolicy" :disabled="!newPolicy.client_ip" class="btn-add">Add Device</button>
          </div>
          <div v-for="p in policies" :key="p.client_ip" class="policy-card">
            <div class="policy-header">
              <span class="policy-ip">{{ p.client_ip }}</span>
              <span class="policy-name" v-if="p.name">{{ p.name }}</span>
              <button v-if="isAdmin" @click="removePolicy(p.client_ip)" class="btn-remove">Remove</button>
            </div>
            <div class="policy-row">
              <span class="policy-label">Disable categories:</span>
              <div class="cat-toggles">
                <label v-for="cat in allPolicyCats" :key="cat" class="cat-check">
                  <input type="checkbox" :checked="p.disabled_categories?.[cat]" @change="togglePolicyCat(p, cat, $event)" :disabled="!isAdmin" />
                  <span>{{ policyCatLabel(cat) }}</span>
                </label>
              </div>
            </div>
            <div class="policy-row">
              <span class="policy-label">Extra blocks:</span>
              <div v-if="isAdmin" class="inline-add">
                <input v-model="policyBlockDomain[p.client_ip]" placeholder="domain.com" @keyup.enter="addPolicyBlock(p)" />
                <button @click="addPolicyBlock(p)" class="btn-add">Block</button>
              </div>
              <div class="tag-list" v-if="Object.keys(p.custom_blocks || {}).length">
                <span v-for="(_, domain) in (p.custom_blocks || {})" :key="domain" class="tag blocked-tag">{{ domain }}<button v-if="isAdmin" @click="removePolicyBlock(p, domain as string)">&times;</button></span>
              </div>
            </div>
            <div class="policy-row">
              <span class="policy-label">Allowed (override):</span>
              <div v-if="isAdmin" class="inline-add">
                <input v-model="policyAllowDomain[p.client_ip]" placeholder="domain.com" @keyup.enter="addPolicyAllow(p)" />
                <button @click="addPolicyAllow(p)" class="btn-add allow">Allow</button>
              </div>
              <div class="tag-list" v-if="Object.keys(p.custom_allows || {}).length">
                <span v-for="(_, domain) in (p.custom_allows || {})" :key="domain" class="tag allow-tag">{{ domain }}<button v-if="isAdmin" @click="removePolicyAllow(p, domain as string)">&times;</button></span>
              </div>
            </div>
          </div>
          <div v-if="!policies.length" class="empty-small">No device policies configured</div>
        </div>
      </div>
    </div>

    <!-- TAB: Network Protection -->
    <div v-if="activeTab === 'netprotect'" class="tab-content">
      <div class="np-toolbar">
        <p class="section-desc" style="margin-bottom:0; flex:1">Block DNS responses whose destination IPs resolve to threat networks.</p>
        <div class="np-toolbar-actions" v-if="isAdmin">
          <div class="np-interval">
            <span class="np-interval-label">Auto-refresh:</span>
            <select v-model="npRefreshMinutes" @change="saveNpInterval" class="np-interval-select">
              <option :value="30">30 min</option>
              <option :value="60">1 hour</option>
              <option :value="180">3 hours</option>
              <option :value="360">6 hours</option>
              <option :value="720">12 hours</option>
              <option :value="1440">24 hours</option>
            </select>
          </div>
          <button @click="refreshNpNow" :disabled="npRefreshing" class="btn-np-refresh">
            {{ npRefreshing ? 'Refreshing...' : 'Refresh Now' }}
          </button>
        </div>
      </div>
      <div class="np-categories">
        <div v-for="cat in npCategories" :key="cat.id" class="np-card" :class="{ enabled: cat.enabled }">
          <div class="np-card-top">
            <div class="np-card-info" @click="openNpDetail(cat)" style="cursor:pointer">
              <span class="np-card-name">{{ cat.name }}</span>
              <span class="np-card-desc">{{ cat.description }}</span>
            </div>
            <div class="np-card-right">
              <span v-if="cat.entry_count" class="np-card-count">{{ cat.entry_count.toLocaleString() }} entries</span>
              <div class="toggle" :class="{ on: cat.enabled, disabled: !isAdmin }" @click="isAdmin && toggleNpCategory(cat)">
                <div class="toggle-knob"></div>
              </div>
            </div>
          </div>
          <div v-if="cat.last_updated" class="np-card-updated">Updated: {{ formatNpDate(cat.last_updated) }}</div>
        </div>
      </div>

      <!-- NP Detail Modal -->
      <div v-if="npDetail" class="modal-overlay" @click.self="npDetail = null">
        <div class="modal-detail" style="max-width:500px">
          <div class="modal-header">
            <h3>{{ npDetail.name }}</h3>
            <button class="modal-close" @click="npDetail = null">&times;</button>
          </div>
          <p class="np-detail-desc">{{ npDetail.description }}</p>
          <div class="ld-meta">
            <span v-if="npDetail.entry_count">{{ npDetail.entry_count.toLocaleString() }} entries loaded</span>
            <span v-if="npDetail.last_updated">Updated: {{ formatNpDate(npDetail.last_updated) }}</span>
            <span :class="npDetail.enabled ? 'np-status-on' : 'np-status-off'">{{ npDetail.enabled ? 'Enabled' : 'Disabled' }}</span>
          </div>
          <div class="np-detail-sources">
            <h4>Sources</h4>
            <div v-for="src in npDetail.sources" :key="src" class="np-detail-source">
              <a :href="src" target="_blank" rel="noopener">{{ src }}</a>
            </div>
          </div>
        </div>
      </div>

      <div class="np-geo">
        <h4>Country Blocking</h4>
        <p class="section-desc">Block DNS responses that resolve to IPs in specific countries via GeoIP lookup.</p>
        <div class="geo-search-wrap" v-if="isAdmin">
          <input v-model="geoSearch" placeholder="Search countries..." @focus="geoDropdownOpen = true" class="geo-search-input" />
          <div v-if="geoDropdownOpen && filteredCountries.length" class="geo-dropdown">
            <div v-for="c in filteredCountries" :key="c.code" class="geo-dropdown-item"
              :class="{ selected: geoBlocked.includes(c.code) }" @click="addGeoCountry(c.code)">
              <span class="geo-dropdown-flag">{{ c.flag }}</span>
              <span class="geo-dropdown-name">{{ c.name }}</span>
              <span class="geo-dropdown-code">{{ c.code }}</span>
              <span v-if="geoBlocked.includes(c.code)" class="geo-dropdown-check">&#x2713;</span>
            </div>
          </div>
        </div>
        <div class="geo-tags" v-if="geoBlocked.length">
          <span v-for="cc in geoBlocked" :key="cc" class="geo-tag">
            <span class="geo-tag-flag">{{ countryFlag(cc) }}</span>
            {{ countryName(cc) }} ({{ cc }})
            <button v-if="isAdmin" @click="removeGeoCountry(cc)" class="geo-remove">&times;</button>
          </span>
        </div>
        <div v-else class="empty-small">No countries blocked</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, inject } from 'vue'
import axios from 'axios'
import { currentUser } from '../auth'

const confirm = inject('confirm') as (opts: any) => Promise<boolean>
const isAdmin = computed(() => currentUser.value?.role === 'admin')

// --- Tabs ---
const activeTab = ref('services')
const tabs = [
  { id: 'services', label: 'Services' },
  { id: 'lists', label: 'Active Lists' },
  { id: 'block-services', label: 'Block Services' },
  { id: 'community', label: 'Community Blocklists' },
  { id: 'premium', label: 'Premium Feeds' },
  { id: 'custom', label: 'Custom Feeds' },
  { id: 'rules', label: 'Rules & Policies' },
  { id: 'netprotect', label: 'Network Protection' },
]

const npEnabled = computed(() => npCategories.value.some(c => c.enabled))
const geoEnabled = computed(() => geoBlocked.value.length > 0)
const npRefreshMinutes = ref(360)
const npRefreshing = ref(false)

async function refreshNpNow() {
  npRefreshing.value = true
  try {
    await axios.post('/api/network-protection/refresh')
    setTimeout(() => { loadNpCategories(); npRefreshing.value = false }, 3000)
  } catch { npRefreshing.value = false }
}

async function saveNpInterval() {
  await axios.put('/api/network-protection/settings', { refresh_minutes: npRefreshMinutes.value })
}

async function loadNpSettings() {
  try {
    const { data } = await axios.get('/api/network-protection/settings')
    npRefreshMinutes.value = data.refresh_minutes || 360
  } catch {}
}

async function toggleNpMaster() {
  const newState = !npEnabled.value
  for (const cat of npCategories.value) {
    if (cat.enabled !== newState) {
      await axios.put(`/api/network-protection/${cat.id}`, { enabled: newState })
    }
  }
  loadNpCategories()
}

const prioritySteps = [
  { num: 1, title: 'Per-Device Allows', result: 'allow' },
  { num: 2, title: 'Global Allowlist', result: 'allow' },
  { num: 3, title: 'Block Services', result: 'block' },
  { num: 4, title: 'Per-Device Blocks', result: 'block' },
  { num: 5, title: 'Custom Block Rules', result: 'block' },
  { num: 6, title: 'Blocklists & Categories', result: 'block' },
  { num: 7, title: 'Network Protection', result: 'block' },
  { num: 8, title: 'Allowed', result: 'allow', pass: true },
]

// --- Blocklist Catalog ---
const showCatalog = ref(false)
const catalogSearch = ref('')
const catalogFilter = ref('')
const catalogAdding = ref('')
const catalogCategories = ['ads', 'malware', 'adult', 'social', 'gambling', 'tracking']

interface CatalogItem {
  name: string; url: string; category: string; description: string; entries?: string
}
interface CatalogProvider {
  name: string; description: string; github: string; lists: CatalogItem[]
}

const blocklistCatalog: CatalogProvider[] = [
  {
    name: 'Hagezi',
    description: 'Multi-level DNS blocklists — from light to ultimate. One of the most popular and well-maintained sources.',
    github: 'https://github.com/hagezi/dns-blocklists',
    lists: [
      { name: 'Hagezi Light', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt', category: 'ads', description: 'Light blocking — minimal false positives, blocks major ad/tracking domains', entries: '70K' },
      { name: 'Hagezi Normal', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt', category: 'ads', description: 'Balanced blocking — recommended for most users', entries: '170K' },
      { name: 'Hagezi Pro', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt', category: 'ads', description: 'Extended blocking — more aggressive, may require allowlisting', entries: '250K' },
      { name: 'Hagezi Pro++', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt', category: 'ads', description: 'Maximum blocking — aggressive, expect some false positives', entries: '370K' },
      { name: 'Hagezi Ultimate', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt', category: 'ads', description: 'Extreme blocking — highest coverage, will need allowlisting', entries: '500K' },
      { name: 'Hagezi TIF (Threat Intel)', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt', category: 'malware', description: 'Threat intelligence feeds — malware, phishing, scam domains', entries: '800K' },
      { name: 'Hagezi Gambling', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/gambling.txt', category: 'gambling', description: 'Online gambling and betting sites', entries: '200K' },
      { name: 'Hagezi Adult', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nsfw.txt', category: 'adult', description: 'NSFW and adult content domains', entries: '500K' },
    ]
  },
  {
    name: 'OISD',
    description: 'One of the internet\'s most comprehensive blocklists. Curated from 800+ sources.',
    github: 'https://github.com/sjhgvr/oisd',
    lists: [
      { name: 'OISD Small', url: 'https://small.oisd.nl/domainswild', category: 'ads', description: 'Conservative blocking — minimal false positives', entries: '70K' },
      { name: 'OISD Big', url: 'https://big.oisd.nl/domainswild', category: 'ads', description: 'Comprehensive blocking — ads, tracking, malware', entries: '200K' },
      { name: 'OISD NSFW', url: 'https://nsfw.oisd.nl/domainswild', category: 'adult', description: 'NSFW content blocking', entries: '350K' },
    ]
  },
  {
    name: 'Steven Black',
    description: 'Unified hosts file with extensions. The classic, long-running blocklist project.',
    github: 'https://github.com/StevenBlack/hosts',
    lists: [
      { name: 'Steven Black Unified', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', category: 'ads', description: 'Adware + malware — the standard unified hosts list', entries: '87K' },
      { name: 'Steven Black + Fakenews', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts', category: 'ads', description: 'Unified + fake news sites', entries: '90K' },
      { name: 'Steven Black + Gambling', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts', category: 'gambling', description: 'Unified + gambling sites', entries: '93K' },
      { name: 'Steven Black + Social', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts', category: 'social', description: 'Unified + social media', entries: '90K' },
      { name: 'Steven Black + Adult', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts', category: 'adult', description: 'Unified + adult content', entries: '114K' },
    ]
  },
  {
    name: '1Hosts',
    description: 'Lightweight, efficient blocklists maintained by badmojr.',
    github: 'https://github.com/badmojr/1Hosts',
    lists: [
      { name: '1Hosts Lite', url: 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt', category: 'ads', description: 'Lite — essential ad and tracker blocking', entries: '40K' },
      { name: '1Hosts Pro', url: 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/domains.txt', category: 'ads', description: 'Pro — extended blocking with more sources', entries: '130K' },
      { name: '1Hosts Xtra', url: 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Xtra/domains.txt', category: 'ads', description: 'Xtra — maximum blocking, may need allowlisting', entries: '200K' },
    ]
  },
  {
    name: 'AdGuard DNS Filter',
    description: 'AdGuard\'s official DNS filter, optimized for DNS-level blocking.',
    github: 'https://github.com/AdguardTeam/AdGuardSDNSFilter',
    lists: [
      { name: 'AdGuard DNS Filter', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', category: 'ads', description: 'Official AdGuard DNS filter — ads, trackers, phishing', entries: '50K' },
    ]
  },
  {
    name: 'Peter Lowe',
    description: 'Well-maintained, compact ad server list. Running since 2009.',
    github: 'https://pgl.yoyo.org/adservers/',
    lists: [
      { name: 'Peter Lowe Ad Servers', url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0', category: 'ads', description: 'Compact, reliable ad server list — zero false positives', entries: '3K' },
    ]
  },
  {
    name: 'DandelionSprout',
    description: 'Nordic-focused filters and anti-malware lists.',
    github: 'https://github.com/DandelionSprout/adfilt',
    lists: [
      { name: 'DandelionSprout Anti-Malware', url: 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt', category: 'malware', description: 'Anti-malware and phishing hosts list', entries: '25K' },
    ]
  },
  {
    name: 'WindowsSpyBlocker',
    description: 'Block Windows telemetry and tracking at DNS level.',
    github: 'https://github.com/crazy-max/WindowsSpyBlocker',
    lists: [
      { name: 'WindowsSpyBlocker (Spy)', url: 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt', category: 'tracking', description: 'Windows telemetry and spying domains', entries: '350' },
    ]
  },
  {
    name: 'Phishing Army',
    description: 'Aggregated phishing domain blocklist, updated frequently.',
    github: 'https://github.com/phishingarmyofficial/phishing_army_blocklist',
    lists: [
      { name: 'Phishing Army', url: 'https://phishing.army/download/phishing_army_blocklist.txt', category: 'malware', description: 'Known phishing domains — updated regularly', entries: '20K' },
      { name: 'Phishing Army Extended', url: 'https://phishing.army/download/phishing_army_blocklist_extended.txt', category: 'malware', description: 'Extended phishing list with more sources', entries: '60K' },
    ]
  },
]

// --- Premium Feeds ---
interface TiFeedProvider {
  id: string; name: string; type: string; description: string;
  placeholder: string; formats?: string[]; website?: string; websiteLabel?: string
}

const tiFeedProviders: TiFeedProvider[] = [
  {
    id: 'kaspersky', name: 'Kaspersky Threat Intelligence', type: 'Commercial',
    description: 'Kaspersky\'s threat data feeds — malicious URLs, botnet C&C, phishing, APT IOCs. Requires Kaspersky TI Portal subscription.',
    placeholder: 'https://opentip.kaspersky.com/api/v1/... or data feed URL',
    formats: ['Domain list', 'Hosts', 'STIX/TAXII'],
    website: 'https://ti.kaspersky.com/', websiteLabel: 'ti.kaspersky.com'
  },
  {
    id: 'paloalto', name: 'Palo Alto Unit 42 / AutoFocus', type: 'Commercial',
    description: 'Unit 42 threat intelligence feeds — malware domains, C2 servers, emerging threats. Requires Palo Alto XSOAR or MineMeld access.',
    placeholder: 'https://autofocus.paloaltonetworks.com/... or MineMeld feed URL',
    formats: ['Domain list', 'Hosts', 'JSON'],
    website: 'https://unit42.paloaltonetworks.com/', websiteLabel: 'unit42.paloaltonetworks.com'
  },
  {
    id: 'fortinet', name: 'Fortinet FortiGuard', type: 'Commercial',
    description: 'FortiGuard threat intelligence — malicious domains, botnets, web filtering categories. Requires FortiGuard subscription.',
    placeholder: 'https://fortiguard.fortinet.com/... or exported feed URL',
    formats: ['Domain list', 'CSV', 'Hosts'],
    website: 'https://fortiguard.fortinet.com/', websiteLabel: 'fortiguard.fortinet.com'
  },
  {
    id: 'crowdstrike', name: 'CrowdStrike Falcon Intelligence', type: 'Commercial',
    description: 'CrowdStrike threat feeds — adversary IOCs, domain indicators, malware families. Requires Falcon subscription.',
    placeholder: 'https://api.crowdstrike.com/... or TAXII feed URL',
    formats: ['Domain list', 'STIX/TAXII', 'JSON'],
    website: 'https://www.crowdstrike.com/products/threat-intelligence/', websiteLabel: 'crowdstrike.com'
  },
  {
    id: 'abuse_ch', name: 'abuse.ch (URLhaus / ThreatFox)', type: 'Free / Community',
    description: 'Free threat intelligence from abuse.ch — URLhaus malware URLs, ThreatFox IOCs, Feodo botnet tracker.',
    placeholder: 'https://urlhaus.abuse.ch/downloads/hostfile/',
    formats: ['Hosts', 'Domain list', 'CSV'],
    website: 'https://abuse.ch/', websiteLabel: 'abuse.ch'
  },
  {
    id: 'openphish', name: 'OpenPhish', type: 'Free / Premium',
    description: 'Automated phishing intelligence — community feed is free, premium has more coverage and faster updates.',
    placeholder: 'https://openphish.com/feed.txt or premium API URL',
    formats: ['URL list', 'Domain list'],
    website: 'https://openphish.com/', websiteLabel: 'openphish.com'
  },
  {
    id: 'alienvault', name: 'AlienVault OTX', type: 'Free / Community',
    description: 'Open Threat Exchange — community-sourced threat data. Free API key required.',
    placeholder: 'https://otx.alienvault.com/api/v1/... or pulse feed URL',
    formats: ['Domain list', 'JSON', 'STIX'],
    website: 'https://otx.alienvault.com/', websiteLabel: 'otx.alienvault.com'
  },
  {
    id: 'cisco_talos', name: 'Cisco Talos Intelligence', type: 'Free / Commercial',
    description: 'Talos threat feeds — IP/domain reputation, malware, spam. Snort/ClamAV-powered intelligence.',
    placeholder: 'https://talosintelligence.com/... or feed URL',
    formats: ['Domain list', 'IP list', 'Hosts'],
    website: 'https://talosintelligence.com/', websiteLabel: 'talosintelligence.com'
  },
]

const tiFeedUrls = reactive<Record<string, string>>({})
const tiFeedApiKeys = reactive<Record<string, string>>({})

const customFeedName = ref('')
const customFeedUrl = ref('')
const customFeedCategory = ref('malware')

async function addTiFeed(ti: TiFeedProvider) {
  let url = tiFeedUrls[ti.id]
  if (!url) return
  // Append API key as query param if provided
  const apiKey = tiFeedApiKeys[ti.id]
  if (apiKey) {
    const sep = url.includes('?') ? '&' : '?'
    url = url + sep + 'api_key=' + encodeURIComponent(apiKey)
  }
  const name = `${ti.name} Feed`
  catalogAdding.value = ti.id
  addError.value = ''
  try {
    await axios.post('/api/blocklists', { name, url, category: 'malware' })
    tiFeedUrls[ti.id] = ''
    tiFeedApiKeys[ti.id] = ''
    loadAll()
  } catch (e: any) {
    addError.value = e.response?.data?.error || `Failed to add ${ti.name} feed`
  } finally {
    catalogAdding.value = ''
  }
}

async function addCustomFeed() {
  if (!customFeedName.value || !customFeedUrl.value) return
  addError.value = ''
  try {
    await axios.post('/api/blocklists', {
      name: customFeedName.value, url: customFeedUrl.value, category: customFeedCategory.value
    })
    customFeedName.value = ''
    customFeedUrl.value = ''
    loadAll()
  } catch (e: any) {
    addError.value = e.response?.data?.error || 'Failed to add feed'
  }
}

function isListAdded(name: string): boolean {
  return lists.value.some(l => l.name === name)
}

const newCatalogCount = computed(() => {
  let count = 0
  for (const provider of blocklistCatalog) {
    for (const item of provider.lists) {
      if (!isListAdded(item.name)) count++
    }
  }
  return count
})

// Active list filtering
const activeListFilter = ref('')
const activeListCategories = computed(() => {
  const cats = new Set(lists.value.map((l: any) => l.category))
  return Array.from(cats).sort()
})
const activeListCategoryCounts = computed(() => {
  const counts: Record<string, number> = {}
  for (const l of lists.value) {
    counts[l.category] = (counts[l.category] || 0) + 1
  }
  return counts
})
const filteredActiveLists = computed(() => {
  if (!activeListFilter.value) return lists.value
  return lists.value.filter((l: any) => l.category === activeListFilter.value)
})

// Update all active lists
const updatingLists = ref(false)
async function updateAllLists() {
  updatingLists.value = true
  addError.value = ''
  try {
    await axios.post('/api/blocklists/update')
    loadAll()
  } catch (e: any) {
    addError.value = e.response?.data?.error || 'Failed to update lists'
  } finally {
    updatingLists.value = false
  }
}

// Delete all active lists
async function deleteAllLists() {
  if (!await confirm({ title: 'Delete All Lists', message: `Delete all ${lists.value.length} active blocklists? All domain filtering will be disabled until new lists are added.`, confirmText: 'Delete All', danger: true })) return
  for (const list of [...lists.value]) {
    try {
      await axios.delete(`/api/blocklists/${encodeURIComponent(list.name)}`)
    } catch {}
  }
  loadAll()
}

// Update schedule
const updateInterval = ref(0)
async function loadUpdateInterval() {
  try {
    const { data } = await axios.get('/api/blocklists/schedule')
    updateInterval.value = data.interval_hours || 0
  } catch {}
}
async function saveUpdateInterval() {
  try {
    await axios.put('/api/blocklists/schedule', { interval_hours: Number(updateInterval.value) })
  } catch {}
}

// Check for updates — refresh catalog info, don't auto-add
async function checkForUpdates() {
  catalogAdding.value = 'checking'
  try {
    await axios.post('/api/blocklists/update')
    loadAll()
  } catch {}
  catalogAdding.value = ''
}

async function addFromCatalog(item: CatalogItem) {
  catalogAdding.value = item.name
  addError.value = ''
  try {
    await axios.post('/api/blocklists', { name: item.name, url: item.url, category: item.category })
    loadAll()
  } catch (e: any) {
    addError.value = e.response?.data?.error || 'Failed to add list'
  } finally {
    catalogAdding.value = ''
  }
}

const filteredCatalog = computed(() => {
  const search = catalogSearch.value.toLowerCase()
  const cat = catalogFilter.value
  return blocklistCatalog
    .map(provider => ({
      ...provider,
      lists: provider.lists.filter(item => {
        const matchSearch = !search || item.name.toLowerCase().includes(search)
          || item.description.toLowerCase().includes(search)
          || provider.name.toLowerCase().includes(search)
        const matchCat = !cat || item.category === cat
        return matchSearch && matchCat
      })
    }))
    .filter(provider => provider.lists.length > 0)
})

const lists = ref<any[]>([])
const totalDomains = ref(0)
const totalLists = ref(0)
const customBlocks = ref<Record<string, string>>({})
const allowlist = ref<string[]>([])
const categories = ref<any[]>([])
const geoBlocked = ref<string[]>([])
const policies = ref<any[]>([])
const policyBlockDomain = reactive<Record<string, string>>({})
const policyAllowDomain = reactive<Record<string, string>>({})

const newName = ref('')
const newUrl = ref('')
const newCategory = ref('ads')
const addError = ref('')
const listDetail = ref<any>(null)
const listDetailDomains = ref<string[]>([])
const listDetailLoading = ref(false)
const listDetailSearch = ref('')

const filteredDetailDomains = computed(() => {
  const q = listDetailSearch.value.toLowerCase()
  if (!q) return listDetailDomains.value
  return listDetailDomains.value.filter(d => d.includes(q))
})

async function openListDetail(list: any) {
  listDetail.value = list
  listDetailDomains.value = []
  listDetailSearch.value = ''
  listDetailLoading.value = true
  try {
    const { data } = await axios.get(`/api/blocklists/${encodeURIComponent(list.name)}/domains`)
    listDetailDomains.value = (data.domains || []).sort()
  } catch {}
  listDetailLoading.value = false
}
const customDomain = ref('')
const customReason = ref('')
const allowDomain = ref('')
const geoInput = ref('')
const geoSearch = ref('')
const geoDropdownOpen = ref(false)

const allCountries = [
  {code:'AF',name:'Afghanistan',flag:'\u{1F1E6}\u{1F1EB}'},{code:'AL',name:'Albania',flag:'\u{1F1E6}\u{1F1F1}'},
  {code:'DZ',name:'Algeria',flag:'\u{1F1E9}\u{1F1FF}'},{code:'AD',name:'Andorra',flag:'\u{1F1E6}\u{1F1E9}'},
  {code:'AO',name:'Angola',flag:'\u{1F1E6}\u{1F1F4}'},{code:'AR',name:'Argentina',flag:'\u{1F1E6}\u{1F1F7}'},
  {code:'AM',name:'Armenia',flag:'\u{1F1E6}\u{1F1F2}'},{code:'AU',name:'Australia',flag:'\u{1F1E6}\u{1F1FA}'},
  {code:'AT',name:'Austria',flag:'\u{1F1E6}\u{1F1F9}'},{code:'AZ',name:'Azerbaijan',flag:'\u{1F1E6}\u{1F1FF}'},
  {code:'BH',name:'Bahrain',flag:'\u{1F1E7}\u{1F1ED}'},{code:'BD',name:'Bangladesh',flag:'\u{1F1E7}\u{1F1E9}'},
  {code:'BY',name:'Belarus',flag:'\u{1F1E7}\u{1F1FE}'},{code:'BE',name:'Belgium',flag:'\u{1F1E7}\u{1F1EA}'},
  {code:'BA',name:'Bosnia and Herzegovina',flag:'\u{1F1E7}\u{1F1E6}'},{code:'BR',name:'Brazil',flag:'\u{1F1E7}\u{1F1F7}'},
  {code:'BG',name:'Bulgaria',flag:'\u{1F1E7}\u{1F1EC}'},{code:'KH',name:'Cambodia',flag:'\u{1F1F0}\u{1F1ED}'},
  {code:'CM',name:'Cameroon',flag:'\u{1F1E8}\u{1F1F2}'},{code:'CA',name:'Canada',flag:'\u{1F1E8}\u{1F1E6}'},
  {code:'CL',name:'Chile',flag:'\u{1F1E8}\u{1F1F1}'},{code:'CN',name:'China',flag:'\u{1F1E8}\u{1F1F3}'},
  {code:'CO',name:'Colombia',flag:'\u{1F1E8}\u{1F1F4}'},{code:'CD',name:'Congo (DRC)',flag:'\u{1F1E8}\u{1F1E9}'},
  {code:'CR',name:'Costa Rica',flag:'\u{1F1E8}\u{1F1F7}'},{code:'HR',name:'Croatia',flag:'\u{1F1ED}\u{1F1F7}'},
  {code:'CU',name:'Cuba',flag:'\u{1F1E8}\u{1F1FA}'},{code:'CY',name:'Cyprus',flag:'\u{1F1E8}\u{1F1FE}'},
  {code:'CZ',name:'Czech Republic',flag:'\u{1F1E8}\u{1F1FF}'},{code:'DK',name:'Denmark',flag:'\u{1F1E9}\u{1F1F0}'},
  {code:'EC',name:'Ecuador',flag:'\u{1F1EA}\u{1F1E8}'},{code:'EG',name:'Egypt',flag:'\u{1F1EA}\u{1F1EC}'},
  {code:'EE',name:'Estonia',flag:'\u{1F1EA}\u{1F1EA}'},{code:'ET',name:'Ethiopia',flag:'\u{1F1EA}\u{1F1F9}'},
  {code:'FI',name:'Finland',flag:'\u{1F1EB}\u{1F1EE}'},{code:'FR',name:'France',flag:'\u{1F1EB}\u{1F1F7}'},
  {code:'GE',name:'Georgia',flag:'\u{1F1EC}\u{1F1EA}'},{code:'DE',name:'Germany',flag:'\u{1F1E9}\u{1F1EA}'},
  {code:'GH',name:'Ghana',flag:'\u{1F1EC}\u{1F1ED}'},{code:'GR',name:'Greece',flag:'\u{1F1EC}\u{1F1F7}'},
  {code:'HK',name:'Hong Kong',flag:'\u{1F1ED}\u{1F1F0}'},{code:'HU',name:'Hungary',flag:'\u{1F1ED}\u{1F1FA}'},
  {code:'IS',name:'Iceland',flag:'\u{1F1EE}\u{1F1F8}'},{code:'IN',name:'India',flag:'\u{1F1EE}\u{1F1F3}'},
  {code:'ID',name:'Indonesia',flag:'\u{1F1EE}\u{1F1E9}'},{code:'IR',name:'Iran',flag:'\u{1F1EE}\u{1F1F7}'},
  {code:'IQ',name:'Iraq',flag:'\u{1F1EE}\u{1F1F6}'},{code:'IE',name:'Ireland',flag:'\u{1F1EE}\u{1F1EA}'},
  {code:'IL',name:'Israel',flag:'\u{1F1EE}\u{1F1F1}'},{code:'IT',name:'Italy',flag:'\u{1F1EE}\u{1F1F9}'},
  {code:'JP',name:'Japan',flag:'\u{1F1EF}\u{1F1F5}'},{code:'JO',name:'Jordan',flag:'\u{1F1EF}\u{1F1F4}'},
  {code:'KZ',name:'Kazakhstan',flag:'\u{1F1F0}\u{1F1FF}'},{code:'KE',name:'Kenya',flag:'\u{1F1F0}\u{1F1EA}'},
  {code:'KP',name:'North Korea',flag:'\u{1F1F0}\u{1F1F5}'},{code:'KR',name:'South Korea',flag:'\u{1F1F0}\u{1F1F7}'},
  {code:'KW',name:'Kuwait',flag:'\u{1F1F0}\u{1F1FC}'},{code:'LV',name:'Latvia',flag:'\u{1F1F1}\u{1F1FB}'},
  {code:'LB',name:'Lebanon',flag:'\u{1F1F1}\u{1F1E7}'},{code:'LY',name:'Libya',flag:'\u{1F1F1}\u{1F1FE}'},
  {code:'LT',name:'Lithuania',flag:'\u{1F1F1}\u{1F1F9}'},{code:'LU',name:'Luxembourg',flag:'\u{1F1F1}\u{1F1FA}'},
  {code:'MY',name:'Malaysia',flag:'\u{1F1F2}\u{1F1FE}'},{code:'MX',name:'Mexico',flag:'\u{1F1F2}\u{1F1FD}'},
  {code:'MD',name:'Moldova',flag:'\u{1F1F2}\u{1F1E9}'},{code:'MN',name:'Mongolia',flag:'\u{1F1F2}\u{1F1F3}'},
  {code:'ME',name:'Montenegro',flag:'\u{1F1F2}\u{1F1EA}'},{code:'MA',name:'Morocco',flag:'\u{1F1F2}\u{1F1E6}'},
  {code:'MM',name:'Myanmar',flag:'\u{1F1F2}\u{1F1F2}'},{code:'NP',name:'Nepal',flag:'\u{1F1F3}\u{1F1F5}'},
  {code:'NL',name:'Netherlands',flag:'\u{1F1F3}\u{1F1F1}'},{code:'NZ',name:'New Zealand',flag:'\u{1F1F3}\u{1F1FF}'},
  {code:'NG',name:'Nigeria',flag:'\u{1F1F3}\u{1F1EC}'},{code:'NO',name:'Norway',flag:'\u{1F1F3}\u{1F1F4}'},
  {code:'OM',name:'Oman',flag:'\u{1F1F4}\u{1F1F2}'},{code:'PK',name:'Pakistan',flag:'\u{1F1F5}\u{1F1F0}'},
  {code:'PA',name:'Panama',flag:'\u{1F1F5}\u{1F1E6}'},{code:'PY',name:'Paraguay',flag:'\u{1F1F5}\u{1F1FE}'},
  {code:'PE',name:'Peru',flag:'\u{1F1F5}\u{1F1EA}'},{code:'PH',name:'Philippines',flag:'\u{1F1F5}\u{1F1ED}'},
  {code:'PL',name:'Poland',flag:'\u{1F1F5}\u{1F1F1}'},{code:'PT',name:'Portugal',flag:'\u{1F1F5}\u{1F1F9}'},
  {code:'QA',name:'Qatar',flag:'\u{1F1F6}\u{1F1E6}'},{code:'RO',name:'Romania',flag:'\u{1F1F7}\u{1F1F4}'},
  {code:'RU',name:'Russia',flag:'\u{1F1F7}\u{1F1FA}'},{code:'SA',name:'Saudi Arabia',flag:'\u{1F1F8}\u{1F1E6}'},
  {code:'RS',name:'Serbia',flag:'\u{1F1F7}\u{1F1F8}'},{code:'SG',name:'Singapore',flag:'\u{1F1F8}\u{1F1EC}'},
  {code:'SK',name:'Slovakia',flag:'\u{1F1F8}\u{1F1F0}'},{code:'SI',name:'Slovenia',flag:'\u{1F1F8}\u{1F1EE}'},
  {code:'ZA',name:'South Africa',flag:'\u{1F1FF}\u{1F1E6}'},{code:'ES',name:'Spain',flag:'\u{1F1EA}\u{1F1F8}'},
  {code:'LK',name:'Sri Lanka',flag:'\u{1F1F1}\u{1F1F0}'},{code:'SD',name:'Sudan',flag:'\u{1F1F8}\u{1F1E9}'},
  {code:'SE',name:'Sweden',flag:'\u{1F1F8}\u{1F1EA}'},{code:'CH',name:'Switzerland',flag:'\u{1F1E8}\u{1F1ED}'},
  {code:'SY',name:'Syria',flag:'\u{1F1F8}\u{1F1FE}'},{code:'TW',name:'Taiwan',flag:'\u{1F1F9}\u{1F1FC}'},
  {code:'TH',name:'Thailand',flag:'\u{1F1F9}\u{1F1ED}'},{code:'TR',name:'Turkey',flag:'\u{1F1F9}\u{1F1F7}'},
  {code:'TM',name:'Turkmenistan',flag:'\u{1F1F9}\u{1F1F2}'},{code:'UA',name:'Ukraine',flag:'\u{1F1FA}\u{1F1E6}'},
  {code:'AE',name:'United Arab Emirates',flag:'\u{1F1E6}\u{1F1EA}'},{code:'GB',name:'United Kingdom',flag:'\u{1F1EC}\u{1F1E7}'},
  {code:'US',name:'United States',flag:'\u{1F1FA}\u{1F1F8}'},{code:'UY',name:'Uruguay',flag:'\u{1F1FA}\u{1F1FE}'},
  {code:'UZ',name:'Uzbekistan',flag:'\u{1F1FA}\u{1F1FF}'},{code:'VE',name:'Venezuela',flag:'\u{1F1FB}\u{1F1EA}'},
  {code:'VN',name:'Vietnam',flag:'\u{1F1FB}\u{1F1F3}'},{code:'YE',name:'Yemen',flag:'\u{1F1FE}\u{1F1EA}'},
  {code:'ZW',name:'Zimbabwe',flag:'\u{1F1FF}\u{1F1FC}'},
]

const filteredCountries = computed(() => {
  const q = geoSearch.value.toLowerCase()
  if (!q) return allCountries.filter(c => !geoBlocked.value.includes(c.code)).slice(0, 15)
  return allCountries.filter(c =>
    (c.name.toLowerCase().includes(q) || c.code.toLowerCase().includes(q))
    && !geoBlocked.value.includes(c.code)
  ).slice(0, 15)
})

function countryFlag(code: string): string {
  return allCountries.find(c => c.code === code)?.flag || ''
}

function countryName(code: string): string {
  return allCountries.find(c => c.code === code)?.name || code
}

async function addGeoCountry(code: string) {
  if (geoBlocked.value.includes(code)) return
  const updated = [...geoBlocked.value, code]
  await axios.put('/api/network-protection/geo', { countries: updated })
  geoSearch.value = ''
  geoDropdownOpen.value = false
  loadAll()
}

const newPolicy = ref({ client_ip: '', name: '' })
const allPolicyCats = ['ads', 'malware', 'adult', 'social', 'gambling', 'tracking']

function policyCatLabel(cat: string) {
  const labels: Record<string, string> = {
    ads: 'Ads & Trackers', malware: 'Malware & Phishing', adult: 'Adult Content',
    social: 'Social Media', gambling: 'Gambling', tracking: 'Analytics & Tracking'
  }
  return labels[cat] || cat
}

const categoryIcons: Record<string, string> = {
  ads: 'AD', malware: 'MW', adult: '18', social: 'SC', gambling: 'GM', tracking: 'TR'
}

function categoryIcon(name: string) {
  return categoryIcons[name] || name.substring(0, 2).toUpperCase()
}

// --- Network Protection ---
const npCategories = ref<any[]>([])

async function loadNpCategories() {
  try {
    const { data } = await axios.get('/api/network-protection')
    npCategories.value = data || []
  } catch (e) {}
}

async function toggleNpCategory(cat: any) {
  try {
    await axios.put(`/api/network-protection/${cat.id}`, { enabled: !cat.enabled })
    loadNpCategories()
  } catch (e) {}
}

function formatNpDate(d: string) {
  return new Date(d).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

const npDetail = ref<any>(null)

function openNpDetail(cat: any) {
  npDetail.value = cat
}

async function loadAll() {
  try {
    const [bl, cb, al, cats, geo, pol] = await Promise.all([
      axios.get('/api/blocklists'),
      axios.get('/api/custom-blocks'),
      axios.get('/api/allowlist'),
      axios.get('/api/categories'),
      axios.get('/api/network-protection/geo'),
      axios.get('/api/policies'),
    ])
    lists.value = bl.data.lists || []
    totalDomains.value = bl.data.total_domains || 0
    totalLists.value = bl.data.total_lists || 0
    customBlocks.value = cb.data || {}
    allowlist.value = al.data || []
    categories.value = cats.data || []
    geoBlocked.value = geo.data || []
    geoInput.value = geoBlocked.value.join(', ')
    policies.value = pol.data || []
  } catch (e) {
    // Load failed silently
  }
}

async function toggleCategory(cat: any) {
  await axios.put(`/api/categories/${cat.name}`, { enabled: !cat.enabled })
  loadAll()
}

async function addList() {
  addError.value = ''
  try {
    await axios.post('/api/blocklists', { name: newName.value, url: newUrl.value, category: newCategory.value })
    newName.value = ''; newUrl.value = ''
    loadAll()
  } catch (e: any) {
    addError.value = e.response?.data?.error || 'Failed to add list'
  }
}

async function removeList(name: string) {
  if (!await confirm({ title: 'Delete List', message: `Delete blocklist "${name}"? The list will be removed from active filtering.`, confirmText: 'Delete', danger: true })) return
  await axios.delete(`/api/blocklists/${encodeURIComponent(name)}`)
  loadAll()
}

async function addCustom() {
  await axios.post('/api/custom-blocks', { domain: customDomain.value, reason: customReason.value })
  customDomain.value = ''; customReason.value = ''
  loadAll()
}

async function removeCustom(domain: string) {
  await axios.delete(`/api/custom-blocks/${domain}`)
  loadAll()
}

async function addAllow() {
  await axios.post('/api/allowlist', { domain: allowDomain.value })
  allowDomain.value = ''
  loadAll()
}

async function removeAllow(domain: string) {
  await axios.delete(`/api/allowlist/${domain}`)
  loadAll()
}

async function saveGeo() {
  const countries = geoInput.value.split(',').map(s => s.trim().toUpperCase()).filter(Boolean)
  await axios.put('/api/network-protection/geo', { countries })
  loadAll()
}

function removeGeoCountry(cc: string) {
  const updated = geoBlocked.value.filter(c => c !== cc)
  geoInput.value = updated.join(', ')
  axios.put('/api/network-protection/geo', { countries: updated }).then(() => loadAll())
}

// --- Policies ---
async function addPolicy() {
  await axios.post('/api/policies', {
    client_ip: newPolicy.value.client_ip, name: newPolicy.value.name,
    disabled_categories: {}, custom_blocks: {}, custom_allows: {},
  })
  newPolicy.value = { client_ip: '', name: '' }
  loadAll()
}
async function removePolicy(ip: string) { await axios.delete(`/api/policies/${ip}`); loadAll() }

async function togglePolicyCat(p: any, cat: string, e: Event) {
  if (!p.disabled_categories) p.disabled_categories = {}
  const checked = (e.target as HTMLInputElement).checked
  if (checked) { p.disabled_categories[cat] = true } else { delete p.disabled_categories[cat] }
  await axios.post('/api/policies', p)
}

async function addPolicyBlock(p: any) {
  const d = policyBlockDomain[p.client_ip]; if (!d) return
  if (!p.custom_blocks) p.custom_blocks = {}; p.custom_blocks[d] = 'device policy'
  await axios.post('/api/policies', p); policyBlockDomain[p.client_ip] = ''; loadAll()
}
async function removePolicyBlock(p: any, d: string) { delete p.custom_blocks[d]; await axios.post('/api/policies', p); loadAll() }

async function addPolicyAllow(p: any) {
  const d = policyAllowDomain[p.client_ip]; if (!d) return
  if (!p.custom_allows) p.custom_allows = {}; p.custom_allows[d] = true
  await axios.post('/api/policies', p); policyAllowDomain[p.client_ip] = ''; loadAll()
}
async function removePolicyAllow(p: any, d: string) { delete p.custom_allows[d]; await axios.post('/api/policies', p); loadAll() }

// --- Block Services ---
const blockServiceCategories = ref<any[]>([])

async function loadBlockServices() {
  try {
    const { data } = await axios.get('/api/block-services')
    blockServiceCategories.value = data || []
  } catch {}
}

// Layout: row1=[AI, Social, Video], row2=[Gaming, Messaging, Audio]
// Order from backend: ai(0), social(1), video(2), audio(3), messaging(4), gaming(5)
// Column distribution: col0=[ai, gaming], col1=[social, messaging], col2=[video, audio]
const bsColumned = computed(() => {
  const cats = blockServiceCategories.value
  if (cats.length < 6) return [cats.slice(0, 2), cats.slice(2, 4), cats.slice(4, 6)]
  return [
    [cats[0], cats[5]], // AI, Gaming
    [cats[1], cats[4]], // Social, Messaging
    [cats[2], cats[3]], // Video, Audio
  ]
})

const bsTotalServices = computed(() => {
  return blockServiceCategories.value.reduce((sum: number, cat: any) => sum + cat.services.length, 0)
})
const bsTotalBlocked = computed(() => {
  return blockServiceCategories.value.reduce((sum: number, cat: any) =>
    sum + cat.services.filter((s: any) => s.enabled).length, 0)
})
const bsTotalDomains = computed(() => {
  let count = 0
  for (const cat of blockServiceCategories.value) {
    for (const svc of cat.services) {
      if (svc.enabled) count += svc.domains.length
    }
  }
  return count
})

// Flat list of all enabled blocked services (for Active Lists tab)
const activeBlockedServices = computed(() => {
  const result: any[] = []
  for (const cat of blockServiceCategories.value) {
    for (const svc of cat.services) {
      if (svc.enabled) {
        result.push({ ...svc, category: cat.name })
      }
    }
  }
  return result
})

const activeServiceDomains = computed(() => {
  return activeBlockedServices.value.reduce((sum: number, svc: any) => sum + svc.domains.length, 0)
})

function bsCatEnabledCount(cat: any): number {
  return cat.services.filter((s: any) => s.enabled).length
}
function bsCatAllEnabled(cat: any): boolean {
  return cat.services.length > 0 && cat.services.every((s: any) => s.enabled)
}
function bsCatPartial(cat: any): boolean {
  const cnt = bsCatEnabledCount(cat)
  return cnt > 0 && cnt < cat.services.length
}
function svcInitials(name: string): string {
  return name.split(/[\s/]+/).map((w: string) => w[0]).join('').substring(0, 2).toUpperCase()
}

async function toggleBsCategory(cat: any) {
  const newState = !bsCatAllEnabled(cat)
  await axios.put(`/api/block-services/category/${cat.id}`, { enabled: newState })
  loadBlockServices()
}

async function toggleBsService(svc: any) {
  await axios.put(`/api/block-services/service/${svc.id}`, { enabled: !svc.enabled })
  loadBlockServices()
}

function closeGeoDropdown(e: MouseEvent) {
  const wrap = (e.target as HTMLElement).closest('.geo-search-wrap')
  if (!wrap) geoDropdownOpen.value = false
}
onMounted(() => {
  loadAll()
  loadNpCategories()
  loadNpSettings()
  loadUpdateInterval()
  loadBlockServices()
  document.addEventListener('click', closeGeoDropdown)
})
</script>

<style scoped>
.blocklists h2 { margin-bottom: 16px; }

/* Tabs */
.tabs {
  display: flex; gap: 2px; margin-bottom: 20px; background: var(--bg-card);
  border-radius: 10px; padding: 4px; border: 1px solid var(--border);
}
.tab-btn {
  flex: 1; padding: 9px 12px; background: transparent; border: none;
  color: var(--text-secondary); border-radius: 8px; cursor: pointer;
  font-size: 0.84rem; font-weight: 500; transition: all 0.15s; white-space: nowrap;
}
.tab-btn:hover { color: var(--text-primary); background: var(--bg-hover); }
.tab-btn.active { background: var(--accent); color: #fff; }

.tab-content { animation: fadeIn 0.15s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

/* Services layout */
.services-layout { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }
.services-left { display: flex; flex-direction: column; gap: 16px; }
.services-right { position: sticky; top: 20px; }
.services-section { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
.services-section h3 { color: var(--text-primary); font-size: 1rem; margin-bottom: 4px; }

.svc-list { display: flex; flex-direction: column; gap: 6px; margin-top: 12px; }
.svc-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; transition: all 0.15s;
}
.svc-item:hover { border-color: var(--text-dim); }
.svc-item.disabled { opacity: 0.45; }
.svc-item.master { border-left: 3px solid var(--accent); }
.svc-item.master.disabled { border-left-color: var(--text-dim); }

.svc-icon {
  width: 36px; height: 36px; border-radius: 8px; display: flex;
  align-items: center; justify-content: center;
  font-size: 0.7rem; font-weight: 700; background: var(--bg-hover); color: var(--text-secondary);
}
.svc-item:nth-child(1) .svc-icon { background: rgba(239,68,68,0.12); color: #ef4444; }
.svc-item:nth-child(2) .svc-icon { background: rgba(249,115,22,0.12); color: #f97316; }
.svc-item:nth-child(3) .svc-icon { background: rgba(168,85,247,0.12); color: #a855f7; }
.svc-item:nth-child(4) .svc-icon { background: rgba(59,130,246,0.12); color: #3b82f6; }
.svc-item:nth-child(5) .svc-icon { background: rgba(234,179,8,0.12); color: #eab308; }
.svc-item:nth-child(6) .svc-icon { background: rgba(14,165,233,0.12); color: #0ea5e9; }
.svc-icon-np { background: rgba(249,115,22,0.12) !important; color: #f97316 !important; }
.svc-icon-bs { background: rgba(236,72,153,0.12) !important; color: #ec4899 !important; }
.svc-icon-geo { background: rgba(139,92,246,0.12) !important; color: #8b5cf6 !important; }

/* Block Services summary in Services tab */
.svc-bs-cats {
  display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px;
}
.svc-bs-cat {
  display: flex; align-items: center; gap: 6px; padding: 4px 10px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px;
  font-size: 0.75rem; opacity: 0.5; transition: all 0.15s;
}
.svc-bs-cat.active { opacity: 1; border-color: var(--accent); }
.svc-bs-cat-icon {
  width: 20px; height: 20px; border-radius: 5px; display: flex;
  align-items: center; justify-content: center;
  font-size: 0.5rem; font-weight: 800;
}
.svc-bs-cat-name { color: var(--text-primary); font-weight: 500; }
.svc-bs-cat-count { color: var(--text-muted); font-family: monospace; font-size: 0.7rem; }

/* Active Lists sections */
.al-section { margin-top: 16px; }
.al-section-title { color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 8px; }
.al-row-svc { border-left: 3px solid #ec4899; }
.list-cat-badge.service { background: rgba(236,72,153,0.15); color: #ec4899; }

.svc-info { flex: 1; }
.svc-name { color: var(--text-primary); font-weight: 500; font-size: 0.88rem; display: block; text-transform: capitalize; }
.svc-count { color: var(--text-muted); font-size: 0.75rem; }

.priority-chain.compact .priority-step { padding: 6px 10px; }
.priority-chain.compact .priority-num { width: 22px; height: 22px; font-size: 0.65rem; }
.priority-chain.compact .priority-title { font-size: 0.8rem; }
.priority-chain.compact .priority-desc { display: none; }
.priority-chain.compact .priority-result { font-size: 0.65rem; padding: 1px 6px; }

/* Rules grid layout */
.rules-grid { display: grid; grid-template-columns: 1fr 1fr 2fr; gap: 16px; }
.rules-col { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
.rules-col.wide { grid-column: span 1; }
.rules-title { font-size: 0.95rem; margin-bottom: 4px; }
.allow-title { color: #34d399 !important; }
.block-title { color: #f87171 !important; }
.policy-title { color: #fbbf24 !important; }
.add-form.compact { gap: 6px; margin-bottom: 10px; }
.add-form.compact input { min-width: 80px; }

.section {
  background: var(--bg-card); border-radius: 12px; padding: 20px;
  border: 1px solid var(--border); margin-bottom: 20px;
  border-left: 3px solid var(--border);
}
.section h3 { color: var(--text-secondary); font-size: 1rem; margin-bottom: 4px; }
.section-desc { color: var(--text-dim); font-size: 0.8rem; margin-bottom: 16px; }

/* Legacy categories grid (kept for compat) */
.categories-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px;
}
.cat-card {
  display: flex; align-items: center; gap: 12px; padding: 14px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; transition: all 0.15s;
}
.cat-card:hover { border-color: var(--text-dim); }
.cat-card.disabled { opacity: 0.4; }
.cat-icon {
  width: 40px; height: 40px; border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.75rem; font-weight: 700;
}
/* Each category gets its own icon color */
.cat-card:nth-child(1) .cat-icon { background: rgba(239,68,68,0.12); color: #ef4444; } /* ads */
.cat-card:nth-child(2) .cat-icon { background: rgba(249,115,22,0.12); color: #f97316; } /* malware */
.cat-card:nth-child(3) .cat-icon { background: rgba(168,85,247,0.12); color: #a855f7; } /* adult */
.cat-card:nth-child(4) .cat-icon { background: rgba(59,130,246,0.12); color: #3b82f6; } /* social */
.cat-card:nth-child(5) .cat-icon { background: rgba(234,179,8,0.12); color: #eab308; } /* gambling */
.cat-card:nth-child(6) .cat-icon { background: rgba(14,165,233,0.12); color: #0ea5e9; } /* tracking */
.cat-info { flex: 1; }
.cat-name { display: block; color: var(--text-primary); font-weight: 600; font-size: 0.9rem; text-transform: capitalize; }
.cat-count { font-size: 0.75rem; color: var(--text-muted); }

.toggle {
  width: 40px; height: 22px; border-radius: 11px; background: var(--text-dim);
  position: relative; transition: background 0.2s;
}
.toggle.on { background: #22c55e; }
.toggle-knob {
  width: 18px; height: 18px; border-radius: 50%; background: #fff;
  position: absolute; top: 2px; left: 2px; transition: transform 0.2s;
}
.toggle.on .toggle-knob { transform: translateX(18px); }

/* Forms */
.add-form {
  display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
}
.add-form input, .add-form select {
  padding: 8px 12px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; flex: 1; min-width: 120px;
  transition: border-color 0.15s;
}
.add-form input::placeholder { color: var(--text-dim); }
.url-input { flex: 2 !important; }

.btn-add {
  padding: 8px 20px; background: #ef4444; color: #fff; border: none;
  border-radius: 6px; cursor: pointer; white-space: nowrap; transition: opacity 0.15s;
}
.btn-add:hover:not(:disabled) { opacity: 0.85; }
.btn-add.allow { background: #22c55e; }
.btn-add.geo { background: #8b5cf6; }
.btn-add:disabled { opacity: 0.3; cursor: not-allowed; }

/* Lists */
.list-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 0; border-bottom: 1px solid var(--border);
}
.list-info { display: flex; flex-direction: column; gap: 2px; }
.list-header { display: flex; align-items: center; gap: 8px; }
.list-name { color: var(--text-primary); font-weight: 500; }
.list-cat-badge {
  padding: 1px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: 600;
  text-transform: uppercase;
}
.list-cat-badge.ads { background: rgba(239,68,68,0.15); color: #ef4444; }
.list-cat-badge.malware { background: rgba(249,115,22,0.15); color: #f97316; }
.list-cat-badge.adult { background: rgba(168,85,247,0.15); color: #a855f7; }
.list-cat-badge.social { background: rgba(59,130,246,0.15); color: #3b82f6; }
.list-cat-badge.gambling { background: rgba(234,179,8,0.15); color: #eab308; }
.list-cat-badge.tracking { background: rgba(14,165,233,0.15); color: #0ea5e9; }
.list-cat-badge.uncategorized { background: rgba(100,116,139,0.15); color: var(--text-muted); }

.list-count { color: var(--accent); font-size: 0.8rem; }
.list-url { color: var(--text-dim); font-size: 0.8rem; word-break: break-all; }

.btn-remove {
  padding: 4px 12px; background: transparent; border: 1px solid #ef4444;
  color: #ef4444; border-radius: 4px; cursor: pointer; font-size: 0.8rem;
  transition: background 0.15s;
}
.btn-remove:hover { background: rgba(239,68,68,0.1); }

/* Active list rows */
.al-list { display: flex; flex-direction: column; gap: 6px; margin-top: 16px; }
.al-row {
  display: flex; align-items: center; gap: 14px; padding: 12px 16px;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; transition: all 0.15s;
}
.al-row:hover { border-color: var(--accent); background: var(--bg-hover); }
.al-row-info { flex: 1; min-width: 0; }
.al-row-name { color: var(--text-primary); font-weight: 600; font-size: 0.9rem; display: block; }
.al-row-url { color: var(--text-dim); font-size: 0.72rem; display: block; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.al-row-count { color: var(--accent); font-size: 0.82rem; font-weight: 500; white-space: nowrap; flex-shrink: 0; }
.btn-delete-row {
  background: none; border: 1px solid rgba(239,68,68,0.3); color: #ef4444; cursor: pointer;
  font-size: 0.78rem; padding: 4px 12px; border-radius: 5px; transition: all 0.15s; flex-shrink: 0;
  font-weight: 500;
}
.btn-delete-row:hover { background: rgba(239,68,68,0.1); border-color: #ef4444; }

/* Active lists toolbar */
.al-toolbar { display: flex; gap: 12px; align-items: flex-start; margin-bottom: 16px; flex-wrap: wrap; }
.al-actions { display: flex; gap: 8px; flex-shrink: 0; padding-top: 2px; }
.btn-update-now {
  padding: 8px 16px; background: var(--accent); color: #fff; border: none;
  border-radius: 6px; cursor: pointer; font-size: 0.82rem; white-space: nowrap; transition: opacity 0.15s;
}
.btn-update-now:hover:not(:disabled) { opacity: 0.85; }
.btn-update-now:disabled { opacity: 0.5; cursor: wait; }
.btn-delete-all {
  padding: 8px 16px; background: none; color: #ef4444; border: 1px solid rgba(239,68,68,0.3);
  border-radius: 6px; cursor: pointer; font-size: 0.82rem; white-space: nowrap; transition: all 0.15s;
}
.btn-delete-all:hover:not(:disabled) { background: rgba(239,68,68,0.1); border-color: #ef4444; }
.btn-delete-all:disabled { opacity: 0.3; cursor: not-allowed; }
.filter-count {
  font-size: 0.68rem; opacity: 0.7; margin-left: 2px;
}

/* Check for updates button */
.btn-check-updates {
  padding: 7px 16px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8));
  color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.82rem;
  transition: opacity 0.15s; white-space: nowrap;
}
.btn-check-updates:hover { opacity: 0.85; }
.btn-check-updates:disabled { opacity: 0.5; cursor: wait; }

.al-filters-row {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  margin-bottom: 12px; flex-wrap: wrap;
}
.al-schedule-inline {
  display: flex; align-items: center; gap: 8px; flex-shrink: 0;
}
.schedule-select {
  padding: 5px 10px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.82rem; cursor: pointer;
}

/* List detail modal */
.modal-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex;
  align-items: center; justify-content: center; z-index: 100;
}
.modal-detail {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px;
  padding: 24px; width: 600px; max-width: 95vw; max-height: 85vh; display: flex; flex-direction: column;
  box-shadow: 0 16px 48px rgba(0,0,0,0.3);
}
.modal-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
.modal-header h3 { color: var(--text-primary); font-size: 1.1rem; }
.modal-close { background: none; border: none; color: var(--text-dim); font-size: 1.5rem; cursor: pointer; line-height: 1; }
.modal-close:hover { color: var(--text-primary); }

.ld-meta { display: flex; gap: 16px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
.ld-meta span { color: var(--text-secondary); font-size: 0.85rem; }
.ld-url { color: var(--text-dim) !important; font-size: 0.75rem !important; word-break: break-all; }
.ld-loading { color: var(--text-muted); font-size: 0.85rem; padding: 20px 0; text-align: center; }

.ld-domains { flex: 1; min-height: 0; display: flex; flex-direction: column; }
.ld-domains-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.ld-domains-header span { color: var(--text-muted); font-size: 0.8rem; }
.ld-search {
  padding: 5px 10px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.82rem; width: 180px;
}
.ld-search::placeholder { color: var(--text-dim); }

.ld-domain-list {
  flex: 1; overflow-y: auto; max-height: 400px;
  background: var(--bg-input); border-radius: 8px; padding: 4px 0;
}
.ld-domain {
  padding: 4px 14px; font-family: monospace; font-size: 0.8rem;
  color: var(--text-primary); border-bottom: 1px solid var(--border);
}
.ld-domain:last-child { border-bottom: none; }
.ld-domain:hover { background: var(--bg-hover); }

.stats-bar {
  margin-top: 12px; padding: 8px 12px; background: var(--bg-input);
  border-radius: 6px; color: var(--text-muted); font-size: 0.85rem;
}

/* Geo tags */
.geo-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
.geo-tag {
  display: flex; align-items: center; gap: 6px; padding: 4px 10px;
  background: rgba(139,92,246,0.15); color: #8b5cf6; border-radius: 6px;
  font-size: 0.85rem; font-weight: 600;
}
.geo-remove {
  background: none; border: none; color: #8b5cf6; cursor: pointer;
  font-size: 1.1rem; line-height: 1; transition: opacity 0.15s;
}
.geo-remove:hover { opacity: 0.7; }

.error-msg {
  background: rgba(239,68,68,0.1); border: 1px solid #ef4444; color: #ef4444;
  padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 0.85rem;
}
.empty { padding: 20px; text-align: center; color: var(--text-dim); }

/* Catalog */
.section-catalog { border-left-color: #818cf8; }
.section-catalog h3 { color: #818cf8 !important; }
.section-header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.btn-toggle-catalog {
  padding: 6px 16px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8));
  color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.82rem;
  transition: opacity 0.15s;
}
.btn-toggle-catalog:hover { opacity: 0.85; }

.catalog { margin-top: 12px; }
.catalog-search { margin-bottom: 16px; }
.catalog-search input {
  width: 100%; padding: 9px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; margin-bottom: 8px;
  transition: border-color 0.15s;
}
.catalog-search input::placeholder { color: var(--text-dim); }
.catalog-filters { display: flex; gap: 6px; flex-wrap: wrap; }
.catalog-filter-btn {
  padding: 4px 12px; border: 1px solid var(--border); background: var(--bg-input);
  color: var(--text-secondary); border-radius: 20px; cursor: pointer; font-size: 0.78rem;
  text-transform: capitalize; transition: all 0.15s;
}
.catalog-filter-btn:hover { border-color: var(--text-dim); }
.catalog-filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }

.catalog-provider { margin-bottom: 20px; }
.provider-header {
  display: flex; justify-content: space-between; align-items: flex-start;
  padding: 10px 14px; background: var(--bg-input); border-radius: 10px 10px 0 0;
  border: 1px solid var(--border); border-bottom: none;
}
.provider-info { display: flex; flex-direction: column; gap: 2px; }
.provider-name { color: var(--text-primary); font-weight: 600; font-size: 0.95rem; }
.provider-desc { color: var(--text-muted); font-size: 0.78rem; line-height: 1.4; max-width: 500px; }
.provider-link {
  color: var(--accent); font-size: 0.78rem; text-decoration: none;
  padding: 3px 10px; border: 1px solid var(--accent); border-radius: 4px;
  transition: all 0.15s; flex-shrink: 0;
}
.provider-link:hover { background: var(--accent-glow); }

.catalog-lists {
  border: 1px solid var(--border); border-radius: 0 0 10px 10px; overflow: hidden;
}
.catalog-item {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 10px 14px; border-bottom: 1px solid var(--border); transition: background 0.1s;
}
.catalog-item:last-child { border-bottom: none; }
.catalog-item:hover { background: var(--bg-hover); }
.catalog-item.added { opacity: 0.6; }
.catalog-item-info { flex: 1; min-width: 0; }
.catalog-item-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.catalog-item-name { color: var(--text-primary); font-weight: 500; font-size: 0.88rem; }
.catalog-item-size { color: var(--text-dim); font-size: 0.72rem; font-family: monospace; }
.catalog-item-desc { color: var(--text-muted); font-size: 0.78rem; display: block; margin-top: 2px; }

.btn-catalog-add {
  padding: 5px 16px; background: var(--accent); color: #fff; border: none;
  border-radius: 6px; cursor: pointer; font-size: 0.8rem; white-space: nowrap;
  transition: all 0.15s; flex-shrink: 0;
}
.btn-catalog-add:hover { background: var(--accent-hover); }
.btn-catalog-add:disabled { opacity: 0.5; cursor: wait; }

/* Community toolbar */
.community-toolbar { display: flex; gap: 12px; align-items: flex-start; margin-bottom: 16px; }
.community-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; padding-top: 2px; }
.new-count-badge {
  padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 700;
  background: rgba(56,189,248,0.15); color: #38bdf8;
}
.btn-add-all-new {
  padding: 7px 16px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8));
  color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.82rem;
  transition: opacity 0.15s; white-space: nowrap;
}
.btn-add-all-new:hover { opacity: 0.85; }
.btn-add-all-new:disabled { opacity: 0.5; cursor: wait; }

.catalog-added-badge {
  padding: 4px 12px; background: rgba(34,197,94,0.12); color: #22c55e;
  border-radius: 6px; font-size: 0.78rem; font-weight: 600; flex-shrink: 0;
}

/* Premium Feeds */
.ti-section { margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border); }
.ti-header { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
.ti-header h4 { color: var(--text-primary); font-size: 0.95rem; margin: 0; }
.ti-badge {
  padding: 2px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.5px;
  background: linear-gradient(135deg, rgba(251,191,36,0.15), rgba(251,146,60,0.15));
  color: #fbbf24; border: 1px solid rgba(251,191,36,0.25);
}

.ti-providers { display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }
.ti-card {
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px 16px;
}
.ti-card-custom { border-style: dashed; }
.ti-card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
.ti-card-name { color: var(--text-primary); font-weight: 600; font-size: 0.9rem; }
.ti-card-type {
  padding: 1px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 600;
  background: rgba(100,116,139,0.15); color: var(--text-muted);
}
.ti-card-desc { color: var(--text-muted); font-size: 0.78rem; line-height: 1.4; margin-bottom: 8px; }

.ti-card-formats { display: flex; gap: 4px; margin-bottom: 8px; flex-wrap: wrap; }
.ti-format {
  padding: 1px 6px; border-radius: 3px; font-size: 0.68rem;
  background: var(--bg-hover); color: var(--text-secondary);
}

.ti-add-form { display: flex; gap: 6px; flex-wrap: wrap; }
.ti-add-form input {
  padding: 7px 12px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.85rem; flex: 1; min-width: 160px;
  transition: border-color 0.15s;
}
.ti-add-form input::placeholder { color: var(--text-dim); }
.ti-url-input { flex: 2 !important; }
.ti-add-form select {
  padding: 7px 10px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.85rem; min-width: 100px;
}

.ti-website {
  display: inline-block; margin-top: 6px; font-size: 0.75rem;
  color: var(--accent); text-decoration: none;
}
.ti-website:hover { text-decoration: underline; }

/* Network Protection */
.section-netprotect { border-left-color: #f97316; }
.section-netprotect h3 { color: #f97316 !important; }

.np-categories { display: flex; flex-direction: column; gap: 8px; margin-bottom: 20px; }
.np-card {
  display: flex; flex-direction: column; gap: 4px;
  padding: 12px 16px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 10px; border-left: 3px solid var(--text-dim); transition: all 0.15s;
}
.np-card.enabled { border-left-color: #22c55e; }
.np-card-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.np-card-info { flex: 1; }
.np-card-name { color: var(--text-primary); font-weight: 600; font-size: 0.9rem; display: block; }
.np-card-desc { color: var(--text-muted); font-size: 0.78rem; display: block; margin-top: 1px; }
.np-card-right { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.np-card-count { color: var(--accent); font-size: 0.75rem; font-family: monospace; }
.np-card-updated { color: var(--text-dim); font-size: 0.7rem; }
.np-card-info:hover .np-card-name { color: var(--accent); }

.np-detail-desc { color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 12px; line-height: 1.5; }
.np-detail-sources { margin-bottom: 16px; }
.np-detail-sources h4 { color: var(--text-primary); font-size: 0.85rem; margin-bottom: 6px; }
.np-detail-source { margin-bottom: 4px; }
.np-detail-source a { color: var(--accent); font-size: 0.8rem; word-break: break-all; text-decoration: none; }
.np-detail-source a:hover { text-decoration: underline; }
.np-detail-entries { flex: 1; min-height: 0; display: flex; flex-direction: column; }
.np-detail-entries h4 { color: var(--text-primary); font-size: 0.85rem; }
.np-status-on { color: #22c55e; font-weight: 600; }
.np-status-off { color: var(--text-dim); }

/* NP toolbar */
.np-toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.np-toolbar-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.np-interval { display: flex; align-items: center; gap: 6px; }
.np-interval-label { color: var(--text-muted); font-size: 0.8rem; }
.np-interval-select {
  padding: 5px 8px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.82rem;
}
.btn-np-refresh {
  padding: 6px 16px; background: linear-gradient(135deg, var(--accent), var(--brand-secondary, #818cf8));
  color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 0.82rem;
  transition: opacity 0.15s; white-space: nowrap;
}
.btn-np-refresh:hover { opacity: 0.85; }
.btn-np-refresh:disabled { opacity: 0.5; cursor: wait; }

/* API key input */
.ti-apikey-input { max-width: 180px; }

.np-geo { margin-top: 4px; padding-top: 16px; border-top: 1px solid var(--border); }
.np-geo h4 { color: var(--text-primary); font-size: 0.9rem; margin-bottom: 4px; }
.empty-small { padding: 12px; text-align: center; color: var(--text-dim); font-size: 0.82rem; }

/* Country search dropdown */
.geo-search-wrap { position: relative; margin-bottom: 12px; }
.geo-search-input {
  width: 100%; padding: 9px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px; color: var(--text-primary); font-size: 0.9rem; transition: border-color 0.15s;
}
.geo-search-input::placeholder { color: var(--text-dim); }
.geo-dropdown {
  position: absolute; top: 100%; left: 0; right: 0; z-index: 50;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px;
  margin-top: 4px; max-height: 280px; overflow-y: auto;
  box-shadow: 0 8px 24px rgba(0,0,0,0.25);
}
.geo-dropdown-item {
  display: flex; align-items: center; gap: 10px; padding: 8px 14px;
  cursor: pointer; transition: background 0.1s;
}
.geo-dropdown-item:hover { background: var(--bg-hover); }
.geo-dropdown-item.selected { opacity: 0.4; pointer-events: none; }
.geo-dropdown-flag { font-size: 1.1rem; }
.geo-dropdown-name { color: var(--text-primary); font-size: 0.88rem; flex: 1; }
.geo-dropdown-code { color: var(--text-dim); font-size: 0.78rem; font-family: monospace; }
.geo-dropdown-check { color: #22c55e; font-weight: 700; }

.geo-tag-flag { font-size: 0.95rem; margin-right: 2px; }

/* Priority chain */
.section-priority { border-left-color: var(--accent); }
.section-priority h3 { color: var(--accent) !important; }
.priority-chain { display: flex; flex-direction: column; gap: 0; margin-top: 12px; }
.priority-step {
  display: flex; align-items: center; gap: 12px;
  padding: 10px 14px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 8px;
}
.priority-step.step-pass { border-color: rgba(34,197,94,0.3); background: rgba(34,197,94,0.04); }
.priority-num {
  width: 28px; height: 28px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; flex-shrink: 0;
  font-size: 0.75rem; font-weight: 700;
  background: var(--bg-hover); color: var(--text-secondary);
}
.priority-num.pass { background: rgba(34,197,94,0.15); color: #22c55e; font-size: 0.9rem; }
.priority-info { flex: 1; }
.priority-title { color: var(--text-primary); font-weight: 600; font-size: 0.85rem; display: block; }
.priority-desc { color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 1px; }
.priority-result {
  padding: 2px 10px; border-radius: 4px; font-size: 0.7rem; font-weight: 700;
  text-transform: uppercase; flex-shrink: 0;
}
.priority-result.allow { background: rgba(34,197,94,0.12); color: #22c55e; }
.priority-result.block { background: rgba(239,68,68,0.12); color: #ef4444; }
.priority-arrow {
  width: 2px; height: 8px; background: var(--border); margin-left: 23px;
}

/* Policy hints */
.policy-hint { color: var(--text-dim); font-size: 0.73rem; margin: -2px 0 6px; font-style: italic; }

/* Policies */
.policy-card {
  background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-top: 12px;
}
.policy-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.policy-ip { color: var(--text-primary); font-weight: 600; font-family: monospace; }
.policy-name { color: var(--text-muted); font-size: 0.85rem; flex: 1; }
.policy-row { margin-bottom: 10px; }
.policy-label { color: var(--text-muted); font-size: 0.8rem; display: block; margin-bottom: 6px; }

.cat-toggles { display: flex; gap: 12px; flex-wrap: wrap; }
.cat-check { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.cat-check input { accent-color: #ef4444; }
.cat-check span { color: var(--text-secondary); font-size: 0.85rem; }

.inline-add { display: flex; gap: 6px; margin-top: 4px; }
.inline-add input {
  padding: 5px 10px; background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary); font-size: 0.85rem; flex: 1; max-width: 220px;
}

.tag-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.tag { display: flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 6px; font-size: 0.8rem; }
.blocked-tag { background: rgba(239,68,68,0.1); color: #ef4444; }
.allow-tag { background: rgba(34,197,94,0.1); color: #22c55e; }
.tag button { background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; line-height: 1; }

/* Block Services */
.bs-layout { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; align-items: start; }
.bs-col { display: flex; flex-direction: column; gap: 16px; }
.bs-category {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  overflow: hidden;
}
.bs-cat-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; background: var(--bg-input); border-bottom: 1px solid var(--border);
}
.bs-cat-left { display: flex; align-items: center; gap: 10px; }
.bs-cat-icon {
  width: 34px; height: 34px; border-radius: 8px; display: flex;
  align-items: center; justify-content: center;
  font-size: 0.68rem; font-weight: 800; letter-spacing: 0.5px;
}
.bs-cat-icon-ai { background: rgba(139,92,246,0.15); color: #8b5cf6; }
.bs-cat-icon-social { background: rgba(59,130,246,0.15); color: #3b82f6; }
.bs-cat-icon-video { background: rgba(239,68,68,0.15); color: #ef4444; }
.bs-cat-icon-audio { background: rgba(34,197,94,0.15); color: #22c55e; }
.bs-cat-icon-messaging { background: rgba(56,189,248,0.15); color: #38bdf8; }
.bs-cat-icon-gaming { background: rgba(249,115,22,0.15); color: #f97316; }
.bs-cat-name { color: var(--text-primary); font-weight: 600; font-size: 0.95rem; display: block; }
.bs-cat-count { color: var(--text-muted); font-size: 0.75rem; }
.bs-cat-info { display: flex; flex-direction: column; gap: 1px; }

.toggle.partial { background: #f59e0b; }
.toggle.small { width: 34px; height: 18px; border-radius: 9px; }
.toggle.small .toggle-knob { width: 14px; height: 14px; }
.toggle.small.on .toggle-knob { transform: translateX(16px); }

.bs-services {
  display: flex; flex-direction: column;
}
.bs-service {
  display: flex; align-items: center; gap: 10px; padding: 8px 16px;
  border-bottom: 1px solid var(--border); transition: all 0.15s; cursor: pointer;
}
.bs-service:last-child { border-bottom: none; }
.bs-service:hover { background: var(--bg-hover); }
.bs-service.blocked { background: rgba(239,68,68,0.04); }

.bs-svc-logo {
  width: 30px; height: 30px; border-radius: 7px; display: flex;
  align-items: center; justify-content: center;
  font-size: 0.6rem; font-weight: 700; background: var(--bg-hover); color: var(--text-secondary);
  flex-shrink: 0;
}
/* Service logo colors */
.bs-logo-chatgpt { background: rgba(16,163,127,0.15); color: #10a37f; }
.bs-logo-claude { background: rgba(204,133,75,0.15); color: #cc854b; }
.bs-logo-gemini { background: rgba(66,133,244,0.15); color: #4285f4; }
.bs-logo-deepseek { background: rgba(59,130,246,0.15); color: #3b82f6; }
.bs-logo-copilot { background: rgba(0,120,212,0.15); color: #0078d4; }
.bs-logo-perplexity { background: rgba(32,175,229,0.15); color: #20afe5; }
.bs-logo-midjourney { background: rgba(255,255,255,0.1); color: var(--text-primary); }
.bs-logo-grok { background: rgba(255,255,255,0.1); color: var(--text-primary); }
.bs-logo-huggingface { background: rgba(255,213,79,0.15); color: #ffd54f; }

.bs-logo-facebook { background: rgba(24,119,242,0.15); color: #1877f2; }
.bs-logo-instagram { background: rgba(225,48,108,0.15); color: #e1306c; }
.bs-logo-tiktok { background: rgba(255,0,80,0.15); color: #ff0050; }
.bs-logo-twitter { background: rgba(29,161,242,0.15); color: #1da1f2; }
.bs-logo-snapchat { background: rgba(255,252,0,0.15); color: #fffc00; }
.bs-logo-linkedin { background: rgba(0,119,181,0.15); color: #0077b5; }
.bs-logo-reddit { background: rgba(255,69,0,0.15); color: #ff4500; }
.bs-logo-pinterest { background: rgba(189,8,28,0.15); color: #bd081c; }
.bs-logo-threads { background: rgba(255,255,255,0.1); color: var(--text-primary); }

.bs-logo-youtube { background: rgba(255,0,0,0.15); color: #ff0000; }
.bs-logo-netflix { background: rgba(229,9,20,0.15); color: #e50914; }
.bs-logo-twitch { background: rgba(145,70,255,0.15); color: #9146ff; }
.bs-logo-disneyplus { background: rgba(19,60,131,0.15); color: #133c83; }
.bs-logo-hbomax { background: rgba(101,52,183,0.15); color: #6534b7; }
.bs-logo-primevideo { background: rgba(0,168,225,0.15); color: #00a8e1; }

.bs-logo-spotify { background: rgba(30,215,96,0.15); color: #1ed760; }
.bs-logo-applemusic { background: rgba(252,60,68,0.15); color: #fc3c44; }
.bs-logo-deezer { background: rgba(160,54,222,0.15); color: #a036de; }
.bs-logo-soundcloud { background: rgba(255,85,0,0.15); color: #ff5500; }
.bs-logo-tidal { background: rgba(255,255,255,0.1); color: var(--text-primary); }

.bs-logo-whatsapp { background: rgba(37,211,102,0.15); color: #25d366; }
.bs-logo-telegram { background: rgba(38,166,224,0.15); color: #26a6e0; }
.bs-logo-discord { background: rgba(88,101,242,0.15); color: #5865f2; }
.bs-logo-signal { background: rgba(58,118,255,0.15); color: #3a76ff; }
.bs-logo-viber { background: rgba(121,60,173,0.15); color: #793cad; }

.bs-logo-steam { background: rgba(27,40,56,0.2); color: #c7d5e0; }
.bs-logo-epicgames { background: rgba(255,255,255,0.1); color: var(--text-primary); }
.bs-logo-roblox { background: rgba(226,35,26,0.15); color: #e2231a; }
.bs-logo-xboxlive { background: rgba(16,124,16,0.15); color: #107c10; }
.bs-logo-playstation { background: rgba(0,55,145,0.15); color: #003791; }

.bs-svc-info { flex: 1; min-width: 0; }
.bs-svc-name { color: var(--text-primary); font-weight: 500; font-size: 0.85rem; display: block; }
.bs-svc-domains { color: var(--text-muted); font-size: 0.7rem; }
.bs-cat-name { font-size: 0.9rem; }

/* How it Works panel */
.bs-how-it-works {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  padding: 18px;
}
.bs-how-it-works h4 { color: var(--text-primary); font-size: 0.95rem; margin-bottom: 14px; }
.bs-hiw-steps { display: flex; flex-direction: column; gap: 12px; }
.bs-hiw-step { display: flex; gap: 10px; align-items: flex-start; }
.bs-hiw-num {
  width: 24px; height: 24px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; flex-shrink: 0;
  font-size: 0.7rem; font-weight: 700; background: var(--accent); color: #fff;
}
.bs-hiw-text { display: flex; flex-direction: column; gap: 1px; }
.bs-hiw-title { color: var(--text-primary); font-weight: 600; font-size: 0.82rem; }
.bs-hiw-desc { color: var(--text-muted); font-size: 0.74rem; line-height: 1.4; }
.bs-hiw-stats {
  display: flex; gap: 12px; margin-top: 16px; padding-top: 14px;
  border-top: 1px solid var(--border);
}
.bs-hiw-stat {
  flex: 1; text-align: center; padding: 10px 0;
  background: var(--bg-input); border-radius: 8px;
}
.bs-hiw-stat-num { display: block; color: var(--accent); font-size: 1.2rem; font-weight: 700; }
.bs-hiw-stat-label { color: var(--text-muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; }
</style>
