require('dotenv').config();
const express = require('express');
const session = require('express-session');
const exphbs = require('express-handlebars');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const useragent = require('express-useragent');
const axios = require('axios');
const { randomInt } = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Konfigurasi Session
app.use(session({
    secret: process.env.SESSION_SECRET || '8f5d3243ccdd907092db55a28e3c1ea89293385adc0953f337ec9c974cc5522f',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 1 hari
    }
}));


const Handlebars = require('handlebars');
Handlebars.registerHelper('json', function(context) {
    return JSON.stringify(context);
});

// Setup View Engine dengan Handlebars
app.engine('html', exphbs.engine({
    extname: '.html',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views/layouts'),
    partialsDir: path.join(__dirname, 'views/partials'),
    helpers: {
    eq: (v1, v2) => v1 === v2,
    formatDate: (dateString) => {
        return new Date(dateString).toLocaleString();
    }
}
}));
app.set('view engine', 'html');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(useragent.express());

// Database Configuration
const DB_FILE = path.join(__dirname, 'data', 'database.json');
const STATS_FILE = path.join(__dirname, 'data', 'stats.json');

// Initialize database files
const initDatabase = () => {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ 
            urls: [], 
            settings: {
                mobileOnly: false,
                blockBots: true,
                allowedCountries: [],
                blockRedirectUrl: ''
            } 
        }, null, 2));
    }

    if (!fs.existsSync(STATS_FILE)) {
        fs.writeFileSync(STATS_FILE, JSON.stringify({ statistics: [] }, null, 2));
    }
};
initDatabase();

// Password Configuration
const PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Authentication Middleware
const checkAuth = (req, res, next) => {
    if (req.path === '/login' || req.path === '/auth' || req.path === '/logout') {
        return next();
    }
    
    if (req.session && req.session.authenticated) {
        return next();
    }
    
    res.redirect('/login');
};

// Routes
app.get('/', checkAuth, (req, res) => {
    res.redirect('/create');
});

app.get('/login', (req, res) => {
    if (req.session.authenticated) {
        return res.redirect('/');
    }
    res.render('login', { 
        title: 'Login',
        layout: 'auth'
    });
});

app.post('/auth', (req, res) => {
    if (req.body.password === PASSWORD) {
        req.session.authenticated = true;
        return res.redirect('/');
    }
    res.render('login', { 
        title: 'Login',
        error: 'Password salah!',
        layout: 'auth'
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Main App Routes
app.get('/create', checkAuth, (req, res) => {
    res.render('create', {
        title: 'Create Shortlink',
        activePage: 'create' // Data untuk highlight menu aktif
    });
});

app.get('/manage', checkAuth, (req, res) => {
    const db = JSON.parse(fs.readFileSync(DB_FILE));
    res.render('manage', { 
        title: 'Manage URLs',
        activePage: 'manage',
        urls: db.urls.map(url => ({
            ...url,
            targetUrls: url.targetUrls || null // Pastikan properti ini ada
        }))
    });
});

app.get('/stats', checkAuth, (req, res) => {
    const stats = JSON.parse(fs.readFileSync(STATS_FILE));
    const totalVisits = stats.statistics.length;
    const humanVisits = stats.statistics.filter(s => !s.isBot).length;
    const botVisits = stats.statistics.filter(s => s.isBot).length;
    const blockedVisits = stats.statistics.filter(s => s.blocked).length;
    
    res.render('stats', { 
        title: 'Statistics',
        activePage: 'stats',
        totalVisits,
        humanVisits,
        botVisits,
        blockedVisits,
        recentActivities: stats.statistics.slice(-10).reverse()
    });
});

// ... (bagian require dan setup awal tetap sama)

// Fungsi untuk baca/simpan settings
const getSettings = () => {
    const db = JSON.parse(fs.readFileSync(DB_FILE));
    return db.settings || {
        mobileOnly: false,
        blockBots: true,
        allowedCountries: [],
        blockRedirectUrl: ''
    };
};

const saveSettings = (newSettings) => {
    const db = JSON.parse(fs.readFileSync(DB_FILE));
    db.settings = {
        ...db.settings,
        ...newSettings
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return db.settings;
};

// Route untuk settings
app.get('/settings', checkAuth, (req, res) => {
    const settings = getSettings();
    const countries = [
        { code: 'US', name: 'United States' },
        { code: 'ID', name: 'Indonesia' },
        { code: 'SG', name: 'Singapore' },
        // Tambahkan negara lain sesuai kebutuhan
    ];
    
    res.render('settings', {
        title: 'Settings',
        activePage: 'settings',
        settings,
        countries: countries.map(country => ({
            ...country,
            selected: settings.allowedCountries.includes(country.code)
        }))
    });
});

app.post('/api/settings', checkAuth, (req, res) => {
    try {
        const { settings } = req.body;
        const savedSettings = saveSettings({
            mobileOnly: settings.mobileOnly,
            blockBots: settings.blockBots,
            allowedCountries: settings.allowedCountries || [],
            blockRedirectUrl: settings.blockRedirectUrl || ''
        });
        
        res.json({ 
            success: true,
            settings: savedSettings 
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Failed to save settings',
            details: error.message 
        });
    }
});

// Batch create short URLs
// Di endpoint POST /api/shorten/batch
app.post('/api/shorten/batch', checkAuth, async (req, res) => {
    const { urls, randomRedirect } = req.body;
    
    if (!urls || urls.length === 0) {
        return res.status(400).json({ error: 'URLs are required' });
    }

    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE));
        const slug = generateSlug();
        
        const newUrl = {
            id: uuidv4(),
            shortUrl: slug,
            createdAt: new Date().toISOString(),
            isActive: true,
            urlType: randomRedirect ? 'random-redirect' : 'batch',
            targetUrls: urls,
            randomRedirect: randomRedirect || false
        };
        
        db.urls.push(newUrl);
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        
        res.json({ 
            success: true,
            shortUrl: `${req.protocol}://${req.get('host')}/${slug}`,
            url: newUrl
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint untuk menghapus URL dari random redirect
app.delete('/api/urls/:id/remove-target', checkAuth, (req, res) => {
    const { id } = req.params;
    const { targetUrl } = req.body;

    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE));
        const urlIndex = db.urls.findIndex(u => u.id === id);
        
        if (urlIndex === -1) {
            return res.status(404).json({ error: 'URL not found' });
        }

        const url = db.urls[urlIndex];
        
        if (!url.targetUrls || !Array.isArray(url.targetUrls)) {
            return res.status(400).json({ error: 'Not a random redirect URL' });
        }

        // Simpan jumlah URL sebelum dihapus
        const originalCount = url.targetUrls.length;
        
        // Filter out the target URL
        url.targetUrls = url.targetUrls.filter(u => u !== targetUrl);

        // Jika hanya tersisa 1 URL, ubah menjadi single URL
        if (url.targetUrls.length === 1) {
            db.urls[urlIndex] = {
                ...url,
                originalUrl: url.targetUrls[0],
                targetUrls: undefined,
                randomRedirect: undefined,
                urlType: undefined
            };
        } 
        // Jika habis, hapus seluruhnya
        else if (url.targetUrls.length === 0) {
            db.urls.splice(urlIndex, 1);
        }

        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        
        res.json({ 
            success: true,
            url: db.urls[urlIndex], // Return URL yang sudah diupdate
            wasDeleted: originalCount === 1 // Flag jika terakhir dihapus
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// API Endpoints
app.post('/api/shorten', checkAuth, async (req, res) => {
    const { url, customSlug } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE));
        const slug = customSlug || generateSlug();
        
        const newUrl = {
            id: uuidv4(),
            originalUrl: url,
            shortUrl: slug,
            createdAt: new Date().toISOString(),
            isActive: true
        };
        
        db.urls.push(newUrl);
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        
        res.json({ 
            success: true,
            shortUrl: `${req.protocol}://${req.get('host')}/${slug}`,
            url: newUrl
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/urls/:id', checkAuth, (req, res) => {
    const { id } = req.params;
    
    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE));
        const initialLength = db.urls.length;
        
        db.urls = db.urls.filter(url => url.id !== id);
        
        if (db.urls.length === initialLength) {
            return res.status(404).json({ error: 'URL not found' });
        }
        
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/urls/:id', checkAuth, (req, res) => {
    const { id } = req.params;
    const { isActive } = req.body;
    
    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE));
        const url = db.urls.find(url => url.id === id);
        
        if (!url) {
            return res.status(404).json({ error: 'URL not found' });
        }
        
        url.isActive = isActive === 'true' || isActive === true;
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
        res.json(url);
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Short URL Redirect
app.get('/:slug', async (req, res) => {
    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE));
        const url = db.urls.find(u => u.shortUrl === req.params.slug);
        
        if (!url || !url.isActive) {
            return res.status(404).render('error', {
                title: 'Error',
                message: 'URL tidak ditemukan atau tidak aktif'
            });
        }

        // Handle redirect types
        if (url.urlType === 'random-redirect' && url.targetUrls?.length > 0) {
            const randomIndex = randomInt(0, url.targetUrls.length);
            return res.redirect(url.targetUrls[randomIndex]);
        }
        
        if (url.urlType === 'batch' && url.targetUrls?.length > 0) {
            return res.redirect(url.targetUrls[0]);
        }
        
        // Check settings
        const settings = db.settings || {};
        const isBot = isRequestFromBot(req);
        const isMobile = req.useragent.isMobile;
        const ip = req.ip.replace('::ffff:', '');
        
        // Get complete geo info from ipwho.is
        let geoInfo = {
            ip: ip,
            country: 'Unknown',
            country_code: 'XX',
            flag: {
                img: '',
                emoji: '',
                emoji_unicode: ''
            },
            connection: {
                isp: 'Unknown'
            }
        };

        try {
            const response = await axios.get(`http://ipwho.is/${ip}`);
            if (response.data && response.data.success) {
                geoInfo = {
                    ...response.data,
                    // Ensure all fields exist
                    flag: response.data.flag || {
                        img: '',
                        emoji: '',
                        emoji_unicode: ''
                    },
                    connection: response.data.connection || {
                        isp: 'Unknown'
                    }
                };
            }
        } catch (error) {
            console.error('Error mendapatkan info geolokasi:', error.message);
        }
        
        // Check restrictions
        let shouldBlock = false;
        let blockReason = '';
        
        if (settings.mobileOnly && !isMobile) {
            shouldBlock = true;
            blockReason = 'mobile_only';
        }
        
        if (settings.allowedCountries?.length > 0) {
            if (!settings.allowedCountries.includes(geoInfo.country_code)) {
                shouldBlock = true;
                blockReason = 'country_blocked';
            }
        }
        
        if (isBot && settings.blockBots) {
            shouldBlock = true;
            blockReason = 'bot_detected';
        }
        
        // Prepare visit data with complete geo info
        const visitData = {
            id: uuidv4(),
            urlId: url.id,
            shortUrl: url.shortUrl,
            originalUrl: url.originalUrl || (url.targetUrls?.join(', ') || ''),
            ip: geoInfo.ip,
            userAgent: req.headers['user-agent'],
            isBot,
            isMobile,
            geoInfo: {
                country: geoInfo.country,
                countryCode: geoInfo.country_code,
                city: geoInfo.city,
                region: geoInfo.region,
                postal: geoInfo.postal,
                coordinates: {
                    latitude: geoInfo.latitude,
                    longitude: geoInfo.longitude
                },
                flag: {
                    img: geoInfo.flag.img,
                    emoji: geoInfo.flag.emoji,
                    emoji_unicode: geoInfo.flag.emoji_unicode
                },
                timezone: geoInfo.timezone?.id || 'Unknown',
                isp: geoInfo.connection?.isp || 'Unknown',
                asn: geoInfo.connection?.asn || null,
                org: geoInfo.connection?.org || 'Unknown'
            },
            device: req.useragent.platform,
            browser: req.useragent.browser,
            os: req.useragent.os,
            timestamp: new Date().toISOString(),
            blocked: shouldBlock,
            blockReason
        };

        // Update statistics
        const stats = JSON.parse(fs.readFileSync(STATS_FILE));
        stats.statistics = stats.statistics || [];
        stats.statistics.push(visitData);
        fs.writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
        
        // Handle blocked access
        if (shouldBlock) {
            if (settings.blockRedirectUrl) {
                return res.redirect(settings.blockRedirectUrl);
            }
            return res.status(403).render('error', {
                title: 'Akses Ditolak',
                message: `Akses dibatasi: ${blockReason}`
            });
        }
        
        // Redirect to original URL
        if (url.originalUrl) {
            return res.redirect(url.originalUrl);
        }
        
        // Fallback
        return res.status(404).render('error', {
            title: 'Error',
            message: 'URL tujuan tidak valid'
        });
        
    } catch (error) {
        console.error('Error dalam redirect:', error);
        return res.status(500).render('error', {
            title: 'Server Error',
            message: 'Terjadi kesalahan server'
        });
    }
});

// Helper functions
function generateSlug() {
    return Math.random().toString(36).substring(2, 8);
}

function isRequestFromBot(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const host = req.headers['host'] || '';
    const accept = req.headers['accept'] || '';
    const connection = req.headers['connection'] || '';
    const via = req.headers['via'] || '';
    const xForwardedFor = req.headers['x-forwarded-for'] || '';
    const referer = req.headers['referer'] || '';
    
    // Common security and phishing detection bots (updated 2025)
    const securityBots = [
        // Google security bots
        'google-safe-browsing', 'google-transparency-report',
        
        // Phishing detection services
        'phishtank', 'openphish', 'safebrowsing', 'urlscan',
        'virustotal', 'phishfort', 'certly', 'phishcatch',
        'phishai', 'phishdetect', 'netcraft', 'zvelo',
        'cleantalk', 'sucuri', 'quttera', 'malwarebytes',
        
        // Cloud security providers
        'cloudflare-radar', 'akamai-bot', 'fastly-security',
        'imperva', 'incapsula', 'barracuda', 'fortiguard',
        
        // Browser security features
        'microsoft-safelink', 'safari-fraud-detection',
        'chrome-phishing-protection', 'edge-smartscreen',
        
        // Other security services
        'abuse.ch', 'threatintelligence', 'cyberpatrol',
        'trustedsource', 'websense', 'bluecoat', 'mcafee',
        'symantec', 'kaspersky', 'trendmicro', 'f-secure',
        'paloalto', 'checkpoint', 'sophos', 'bitdefender'
    ];
    
    // Email Service Providers
    const emailProviders = [
        'microsoft-exchange', 'outlook-protection', 'google-mail',
        'gmail', 'yahoo-mail', 'protonmail', 'tutanota',
        'mail.ru', 'zoho-mail', 'fastmail', 'icloud-mail',
        'aol-mail', 'mailchimp', 'sendgrid', 'mandrill',
        'postmark', 'sparkpost', 'mailgun', 'amazon-ses',
        'proofpoint', 'mimecast', 'barracuda-email', 'ironport',
        'symantec-email', 'trendmicro-email', 'fortimail',
         'mail.com', 'mail-com', 'mailcom', '1and1-mail', '1und1', // Mail.com dan 1&1 Mail
        'mx-login.mail.com', 'webmail.mail.com', 'mailer.mail.com',
        'mail-checker', 'mail-scanner', 'mail-security'
    
    ];

    const mailComDomainsAndIPs = [
        'mail.com',
        'mx.mail.com',
        'smtp.mail.com',
        'webmail.mail.com',
        'mailer.mail.com',
        '195.182.', // Contoh prefix IP mail.com
        '212.227.', // Contoh prefix IP lain mail.com
        '94.136.' // Contoh prefix IP lain
    ];

    // Deteksi khusus mail.com
    const isMailComBot = mailComDomainsAndIPs.some(pattern => 
        userAgent.includes(pattern) ||
        host.includes(pattern) ||
        xForwardedFor.includes(pattern) ||
        referer.includes('mail.com') ||
        referer.includes('webmail.mail.com')
    );

    if (isMailComBot) return true;

    
    // Domain Registries and DNS Providers
    const domainRegistryPatterns = [
        // Registry Operators
        'verisign', 'nic.', 'registry', 'iana', 'icann', 
        'afilias', 'publicinterestregistry', 'donuts',
        'centralnic', 'neustar', 'nominet', 'kisa', 'twnic',
        
        // Registrars
        'godaddy', 'namecheap', 'enom', 'network solutions',
        'porkbun', 'name.com', 'google domains', 'cloudflare registrar',
        'dynadot', 'hexonet', 'key-systems', 'resellerclub',
        'eurodns', 'ovh', 'hostinger', 'bluehost', 'hostgator',
        
        // TLD-specific
        'cocca', 'dotasia', 'corenic', 'registry.google',
        
        // Common patterns
        'domain-check', 'whois', 'dns-check', 'registry-bot',
        'tld-scanner', 'domain-scanner', 'sld-monitor'
    ];

    // Common Domain Registry User Agents
    const registryUserAgents = [
        'VerisignWhoisBot',
        'GoDaddyDomainsBot',
        'NamecheapDomainMonitor',
        'ICANNValidator',
        'IANADomainScanner',
        'RegistryMonitor'
    ];

    // Check for domain registry patterns
    const isDomainRegistry = domainRegistryPatterns.some(pattern => 
        userAgent.includes(pattern) ||
        host.includes(pattern) ||
        xForwardedFor.includes(pattern) ||
        referer.includes(pattern)
    );

    // Check for known registry user agents
    const isRegistryUserAgent = registryUserAgents.some(ua => 
        userAgent.includes(ua.toLowerCase())
    );

    if (isDomainRegistry || isRegistryUserAgent) {
        return true;
    }

    // Additional WHOIS/DNS specific checks
    const whoisDnsPatterns = [
        'whois', 'rdap', 'domain', 'dns', 'nameserver',
        'ns-check', 'zone-check', 'tld-verify'
    ];

    const isWhoisDnsCheck = whoisDnsPatterns.some(pattern => 
        userAgent.includes(pattern) ||
        req.path.includes(pattern) ||
        req.query.hasOwnProperty('whois') ||
        req.query.hasOwnProperty('dns')
    );

    if (isWhoisDnsCheck) {
        return true;
    }
    
    // Anti-Phishing Communities
    const antiPhishingCommunities = [
        'apwg', 'anti-phishing', 'phish-report', 'phishlabs',
        'cybercrime-tracker', 'abuseipdb', 'malware-hunter',
        'spamhaus', 'surbl', 'uribl', 'dshield', 'shadowserver',
        'team-cymru', 'threatstop', 'threatcrowd', 'alienvault',
        'talosintelligence', 'fireeye', 'crowdstrike', 'paloalto',
        'proofpoint-threat', 'cyren', 'f-secure-labs', 'kaspersky-lab'
    ];
    
    // Common bot patterns
    const botPatterns = [
        // Generic bot indicators
        'bot', 'crawl', 'spider', 'scanner', 'monitor',
        'checker', 'validator', 'fetcher', 'collector',
        'analyzer', 'indexer', 'extractor', 'reader',
        'watcher', 'tracker', 'sniffer', 'harvester',
        
        // Headless browsers
        'headlesschrome', 'headlessfirefox', 'phantomjs',
        'puppeteer', 'playwright', 'selenium', 'webdriver',
        
        // SEO and scraping tools
        'ahrefs', 'moz', 'semrush', 'seokicks', 'seoscanners',
        'screaming frog', 'sitebulb', 'deepcrawl', 'netsparker',
        'httrack', 'wget', 'curl', 'python-requests',
        
        // Monitoring tools
        'pingdom', 'uptimerobot', 'newrelic', 'datadog',
        'statuscake', 'site24x7', 'gtmetrix', 'webpagetest',
        
        // Social media bots
        'facebookexternalhit', 'twitterbot', 'linkedinbot',
        'slackbot', 'discordbot', 'telegrambot', 'whatsapp',
        
        // Feed readers
        'feedfetcher', 'feedparser', 'rss', 'atom', 'syndication'
    ];
    
    // IP-based detection (common bot hosting providers)
    const botHostingIPs = [
        'aws', 'google', 'azure', 'cloudflare', 'digitalocean',
        'linode', 'vultr', 'ovh', 'alibaba', 'tencent',
        'hetzner', 'rackspace', 'softlayer', 'awsdns', 'gcp'
    ];
    
    // Check for email providers first
    const isEmailProvider = emailProviders.some(provider => 
        userAgent.includes(provider) ||
        host.includes(provider) ||
        via.includes(provider) ||
        xForwardedFor.includes(provider)
    );
    
    if (isEmailProvider) return true;
    
    // Check for domain/DNS providers
    const isDomainDnsProvider = domainDnsProviders.some(provider => 
        userAgent.includes(provider) ||
        host.includes(provider) ||
        via.includes(provider) ||
        xForwardedFor.includes(provider)
    );
    
    if (isDomainDnsProvider) return true;
    
    // Check for anti-phishing communities
    const isAntiPhishing = antiPhishingCommunities.some(community => 
        userAgent.includes(community) ||
        host.includes(community) ||
        via.includes(community) ||
        xForwardedFor.includes(community)
    );
    
    if (isAntiPhishing) return true;
    
    // Check for security bots
    const isSecurityBot = securityBots.some(bot => 
        userAgent.includes(bot) ||
        host.includes(bot) ||
        via.includes(bot)
    );
    
    if (isSecurityBot) return true;
    
    // Check for common bot patterns
    const isCommonBot = botPatterns.some(pattern => 
        userAgent.includes(pattern) ||
        accept.includes(pattern) ||
        connection.includes('keep-alive') && userAgent.includes('python')
    );
    
    if (isCommonBot) return true;
    
    // Check for hosting provider IPs in headers
    const isBotHosting = botHostingIPs.some(hosting => 
        xForwardedFor.includes(hosting) ||
        via.includes(hosting) ||
        host.includes(hosting)
    );
    
    if (isBotHosting && !userAgent.includes('mozilla')) return true;
    
    // Additional checks for suspicious behavior
    const suspiciousHeaders = {
        noCookies: !req.headers.cookie,
        noReferer: !referer,
        noAcceptLanguage: !req.headers['accept-language'],
        fastRequest: req.timing && req.timing.duration < 50 // Very fast response time
    };
    
    const suspiciousCount = Object.values(suspiciousHeaders).filter(Boolean).length;
    
    // If multiple suspicious headers and no human-like user agent
    if (suspiciousCount >= 2 && !userAgent.match(/mozilla|chrome|safari|firefox|edge|opera/i)) {
        return true;
    }
    
    // Final check for very obvious bots
    return [
        // Empty user agent
        userAgent.length === 0,
        
        // Known bot user agents
        userAgent.includes('bytespider'), // Bytedance/TikTok bot
        userAgent.includes('petalbot'), // Huawei bot
        userAgent.includes('applebot'), // Apple bot
        userAgent.includes('bingbot'), // Microsoft Bing
        userAgent.includes('yandexbot'), // Yandex
        userAgent.includes('duckduckbot'), // DuckDuckGo
        
        // Headers that indicate automation
        req.headers['x-bot'] !== undefined,
        req.headers['x-crawler'] !== undefined,
        req.headers['x-forwarded-proto'] === 'https' && userAgent.includes('python'),
        
        // Email scanning patterns
        referer.includes('email-protection') || 
        referer.includes('mail-track') ||
        userAgent.includes('email-scanner') ||
        userAgent.includes('link-checker')
    ].some(Boolean);
}

// Endpoint untuk reset activities
app.post('/api/stats/reset', checkAuth, (req, res) => {
    try {
        const stats = { statistics: [] };
        fs.writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ 
            error: 'Failed to reset statistics',
            details: error.message 
        });
    }
});

// Error Handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', {
        title: 'Error',
        message: 'Something went wrong!'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Admin password: ${PASSWORD}`);
});