<?php
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/security.php';

// Dapatkan hash dari URL
$request_uri = $_SERVER['REQUEST_URI'];
$hash = '';

if (preg_match('/\/go\/([a-zA-Z0-9]+)/', $request_uri, $matches)) {
    $hash = $matches[1];
} elseif (preg_match('/\/r\/([a-zA-Z0-9]+)/', $request_uri, $matches)) {
    $hash = $matches[1];
} elseif (isset($_GET['id'])) {
    $hash = $_GET['id'];
}

if (empty($hash)) {
    show_error_page('Link not found', 404);
}

// Cari link berdasarkan hash
$link = get_link_by_hash($hash);

if (!$link || !$link['active']) {
    show_error_page('Link not found or inactive', 404);
}

// Periksa keamanan
block_bots();
block_countries($link['blocked_countries'] ?? []);
block_ips($link['blocked_ips'] ?? []);

if (!empty($link['allowed_referers'])) {
    validate_referer($link['allowed_referers']);
}

// Log kunjungan
$is_bot = is_bot();
log_visit($hash, $is_bot);

// Rotasi link
$target_url = rotate_link($link);

if (empty($target_url)) {
    show_error_page('No valid target URLs available', 500);
}

// Pemeriksaan keamanan URL target
if (!check_url_safety($target_url)) {
    show_error_page('Dangerous URL detected - Redirect blocked', 403);
}

// Tambahkan parameter UTM jika ada
if (!empty($link['utm_params'])) {
    $target_url = add_utm_parameters($target_url, $link['utm_params']);
}

// Handle redirect berdasarkan tipe
if ($link['redirect_style'] === 'interstitial') {
    show_interstitial_page($target_url, $link);
} else {
    // Redirect langsung
    header("Location: $target_url", true, 302);
    exit;
}

/**
 * Fungsi bantuan
 */
function show_interstitial_page($url, $link) {
    $html = $link['interstitial_html'] ?? get_default_interstitial_html();
    
    // Replace template variables
    $replacements = [
        '{{destination}}' => htmlspecialchars($url),
        '{{short_url}}' => htmlspecialchars($_SERVER['REQUEST_URI']),
        '{{domain}}' => htmlspecialchars(parse_url($url, PHP_URL_HOST))
    ];
    
    $html = str_replace(
        array_keys($replacements),
        array_values($replacements),
        $html
    );
    
    header('Content-Type: text/html');
    echo $html;
    exit;
}

function get_default_interstitial_html() {
    return '<!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting...</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                padding: 20px; 
                background: #f5f5f5;
                color: #333;
            }
            .container {
                background: white;
                border-radius: 10px;
                padding: 30px;
                max-width: 600px;
                margin: 20px auto;
                box-shadow: 0 2px 15px rgba(0,0,0,0.1);
            }
            .countdown {
                font-size: 24px;
                margin: 25px 0;
                color: #ff2a6d;
                font-weight: bold;
            }
            #proceed-link {
                display: inline-block;
                margin-top: 20px;
                padding: 12px 25px;
                background: #ff2a6d;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                transition: all 0.3s;
            }
            #proceed-link:hover {
                background: #e61e5b;
                transform: translateY(-2px);
            }
            .url-display {
                margin: 20px 0;
                padding: 10px;
                background: #f9f9f9;
                border-radius: 5px;
                word-break: break-all;
            }
            @media (max-width: 480px) {
                .container {
                    padding: 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>You are being redirected</h1>
            <p>Safety verification in progress...</p>
            
            <div class="url-display">
                Destination: <strong id="dest">{{domain}}</strong>
            </div>
            
            <div class="countdown">Redirecting in <span id="count">5</span> seconds</div>
            
            <a href="{{destination}}" id="proceed-link">Proceed Now</a>
            
            <p style="margin-top: 30px; font-size: 14px; color: #777;">
                This interstitial page helps protect against malicious sites
            </p>
        </div>
        
        <script>
            // Countdown timer
            let seconds = 5;
            const countEl = document.getElementById("count");
            const timer = setInterval(() => {
                seconds--;
                countEl.textContent = seconds;
                if (seconds <= 0) {
                    clearInterval(timer);
                    window.location.href = "{{destination}}";
                }
            }, 1000);
            
            // Skip button
            document.getElementById("proceed-link").addEventListener("click", (e) => {
                e.preventDefault();
                clearInterval(timer);
                window.location.href = "{{destination}}";
            });
            
            // Optional: Send ping to server when user proceeds
            document.getElementById("proceed-link").addEventListener("click", () => {
                fetch("/track/interstitial_skip", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ hash: "<?= $hash ?>" })
                });
            });
        </script>
    </body>
    </html>';
}

function show_error_page($message, $status_code = 400) {
    header("HTTP/1.1 $status_code");
    echo "<!DOCTYPE html>
    <html>
    <head>
        <title>Error</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .error { color: #ff2a6d; margin: 20px; }
        </style>
    </head>
    <body>
        <h1>Error</h1>
        <div class="error">$message</div>
    </body>
    </html>";
    exit;
}

