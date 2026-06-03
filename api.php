<?php
/**
 * ShieldPress Middleman API
 *
 * Host this on your server (Vercel, Railway, or any cheap VPS).
 * Your OpenRouter API key stays here — never exposed to customers.
 *
 * Endpoints:
 * POST /api.php?action=analyze_spam   → AI spam analysis
 * POST /api.php?action=weekly_report  → AI weekly report summary
 *
 * Security:
 * - Validates ShieldPress licence key before processing
 * - Rate limits per licence key (50 requests/day)
 * - Returns JSON responses only
 */

header( 'Content-Type: application/json' );
header( 'Access-Control-Allow-Origin: *' );
header( 'Access-Control-Allow-Methods: POST' );

// ── YOUR KEYS — set these as environment variables ────────────
$OPENROUTER_KEY  = getenv( 'OPENROUTER_KEY' )  ?: 'sk-or-your-key-here';
$LICENCE_SECRET  = getenv( 'LICENCE_SECRET' )  ?: 'your-secret-here';

// ── CONFIG ────────────────────────────────────────────────────
const OPENROUTER_API = 'https://openrouter.ai/api/v1/chat/completions';
const FREE_MODEL     = 'meta-llama/llama-3.3-70b-instruct:free';
const FALLBACK_MODEL = 'openrouter/free';
const RATE_LIMIT     = 50; // requests per licence per day

// ── ONLY ACCEPT POST ──────────────────────────────────────────
if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
    http_response_code( 405 );
    echo json_encode( [ 'error' => 'Method not allowed' ] );
    exit;
}

// ── GET ACTION AND VALIDATE ───────────────────────────────────
$action      = $_GET['action'] ?? '';
$body        = json_decode( file_get_contents( 'php://input' ), true );
$licence_key = $body['licence_key'] ?? '';

if ( empty( $action ) || empty( $licence_key ) ) {
    http_response_code( 400 );
    echo json_encode( [ 'error' => 'Missing action or licence key' ] );
    exit;
}

// ── VALIDATE LICENCE KEY ──────────────────────────────────────
// Simple validation — checks format and against your Lemon Squeezy API
// For now uses a basic format check — upgrade to real LS API after launch
if ( ! validate_licence( $licence_key, $LICENCE_SECRET ) ) {
    http_response_code( 401 );
    echo json_encode( [ 'error' => 'Invalid licence key' ] );
    exit;
}

// ── RATE LIMITING ─────────────────────────────────────────────
if ( ! check_rate_limit( $licence_key ) ) {
    http_response_code( 429 );
    echo json_encode( [ 'error' => 'Rate limit exceeded. Max ' . RATE_LIMIT . ' requests per day.' ] );
    exit;
}

// ── ROUTE TO ACTION ───────────────────────────────────────────
switch ( $action ) {

    case 'analyze_spam':
        handle_spam_analysis( $body, $OPENROUTER_KEY );
        break;

    case 'weekly_report':
        handle_weekly_report( $body, $OPENROUTER_KEY );
        break;

    default:
        http_response_code( 404 );
        echo json_encode( [ 'error' => 'Unknown action: ' . $action ] );
        exit;
}

// ── HANDLERS ──────────────────────────────────────────────────

/**
 * handle_spam_analysis()
 * Analyzes comment text for spam using OpenRouter AI.
 */
function handle_spam_analysis( $body, $api_key ) {

    $text = trim( $body['text'] ?? '' );

    if ( empty( $text ) || strlen( $text ) < 5 ) {
        http_response_code( 400 );
        echo json_encode( [ 'error' => 'No text provided' ] );
        return;
    }

    // Truncate to 500 chars — no need to send more
    $text = substr( $text, 0, 500 );

    $prompt = "You are a spam detection system for a WordPress comment section.\n\nAnalyze this comment and respond ONLY with a JSON object — no other text:\n{\"is_spam\": true or false, \"score\": 0-100, \"reason\": \"brief reason\"}\n\nScoring: 0-30 = legitimate, 31-74 = suspicious, 75-100 = spam.\nLook for: promotional links, generic praise, gibberish, excessive keywords, fake offers.\n\nComment: \"" . addslashes( $text ) . "\"";

    $result = call_openrouter( $prompt, $api_key, 100 );

    if ( ! $result ) {
        http_response_code( 502 );
        echo json_encode( [ 'error' => 'AI service unavailable' ] );
        return;
    }

    // Parse JSON from AI response
    $clean  = preg_replace( '/```json|```/', '', $result );
    $parsed = json_decode( trim( $clean ), true );

    if ( ! is_array( $parsed ) || ! isset( $parsed['is_spam'] ) ) {
        http_response_code( 502 );
        echo json_encode( [ 'error' => 'Invalid AI response' ] );
        return;
    }

    echo json_encode( [
        'success'  => true,
        'is_spam'  => (bool) $parsed['is_spam'],
        'score'    => intval( $parsed['score'] ?? 0 ),
        'reason'   => substr( $parsed['reason'] ?? '', 0, 200 ),
    ] );
}

/**
 * handle_weekly_report()
 * Generates AI analysis paragraph for weekly security report.
 */
function handle_weekly_report( $body, $api_key ) {

    $stats = $body['stats'] ?? [];

    if ( empty( $stats ) ) {
        http_response_code( 400 );
        echo json_encode( [ 'error' => 'No stats provided' ] );
        return;
    }

    $prompt = sprintf(
        "You are a WordPress security expert. Write a 3-4 sentence plain-English security summary for a non-technical website owner. Be friendly and specific. End with one recommendation.\n\nWeekly data:\n- Total threats blocked: %d\n- Firewall events: %d\n- Login attempts blocked: %d\n- Spam blocked: %d\n- Country blocks: %d\n- Period: %s to %s\n\nWrite only the paragraph, no headers.",
        intval( $stats['total'] ?? 0 ),
        intval( $stats['firewall'] ?? 0 ),
        intval( $stats['login'] ?? 0 ),
        intval( $stats['spam'] ?? 0 ),
        intval( $stats['country'] ?? 0 ),
        substr( $stats['period_start'] ?? '', 0, 20 ),
        substr( $stats['period_end'] ?? '', 0, 20 )
    );

    $result = call_openrouter( $prompt, $api_key, 200 );

    if ( ! $result ) {
        http_response_code( 502 );
        echo json_encode( [ 'error' => 'AI service unavailable' ] );
        return;
    }

    echo json_encode( [
        'success'  => true,
        'analysis' => substr( $result, 0, 1000 ),
    ] );
}

// ── OPENROUTER CALL ───────────────────────────────────────────

/**
 * call_openrouter()
 * Makes a request to OpenRouter API using the free model.
 */
function call_openrouter( $prompt, $api_key, $max_tokens = 150 ) {

    $payload = json_encode( [
        'model'       => FREE_MODEL,
        'messages'    => [
            [ 'role' => 'user', 'content' => $prompt ],
        ],
        'max_tokens'  => $max_tokens,
        'temperature' => 0.1,
    ] );

    $ch = curl_init( OPENROUTER_API );
    curl_setopt_array( $ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $api_key,
            'Content-Type: application/json',
            'HTTP-Referer: https://getshieldpress.com',
            'X-Title: ShieldPress',
        ],
    ] );

    $response = curl_exec( $ch );
    $http_code = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    curl_close( $ch );

    if ( $http_code !== 200 || ! $response ) {
        // Try fallback model
        return call_openrouter_fallback( $prompt, $api_key, $max_tokens );
    }

    $data = json_decode( $response, true );
    return $data['choices'][0]['message']['content'] ?? null;
}

/**
 * call_openrouter_fallback()
 * Falls back to openrouter/free if primary model fails.
 */
function call_openrouter_fallback( $prompt, $api_key, $max_tokens ) {

    $payload = json_encode( [
        'model'       => FALLBACK_MODEL,
        'messages'    => [
            [ 'role' => 'user', 'content' => $prompt ],
        ],
        'max_tokens'  => $max_tokens,
        'temperature' => 0.1,
    ] );

    $ch = curl_init( OPENROUTER_API );
    curl_setopt_array( $ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $api_key,
            'Content-Type: application/json',
            'HTTP-Referer: https://getshieldpress.com',
            'X-Title: ShieldPress',
        ],
    ] );

    $response = curl_exec( $ch );
    curl_close( $ch );

    if ( ! $response ) return null;
    $data = json_decode( $response, true );
    return $data['choices'][0]['message']['content'] ?? null;
}

// ── HELPERS ───────────────────────────────────────────────────

/**
 * validate_licence()
 * Basic licence key format validation.
 * Upgrade to real Lemon Squeezy API check after launch.
 */
function validate_licence( $key, $secret ) {
    // Basic format check — alphanumeric with dashes, min 10 chars
    if ( ! preg_match( '/^[a-zA-Z0-9\-]{10,}$/', $key ) ) {
        return false;
    }
    // TODO after launch: ping Lemon Squeezy API to verify key is active
    // For now accept any properly formatted key
    return true;
}

/**
 * check_rate_limit()
 * Simple file-based rate limiting per licence key.
 * Resets every 24 hours.
 */
function check_rate_limit( $key ) {

    $cache_dir  = sys_get_temp_dir() . '/sp_rate/';
    $cache_file = $cache_dir . md5( $key ) . '.json';

    if ( ! is_dir( $cache_dir ) ) {
        mkdir( $cache_dir, 0755, true );
    }

    $today = date( 'Y-m-d' );
    $data  = [ 'date' => $today, 'count' => 0 ];

    if ( file_exists( $cache_file ) ) {
        $saved = json_decode( file_get_contents( $cache_file ), true );
        if ( $saved && $saved['date'] === $today ) {
            $data = $saved;
        }
    }

    if ( $data['count'] >= RATE_LIMIT ) {
        return false;
    }

    $data['count']++;
    file_put_contents( $cache_file, json_encode( $data ) );
    return true;
}
