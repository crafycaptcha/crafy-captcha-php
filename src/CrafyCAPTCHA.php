<?php

namespace Crafy\Captcha;

use Exception;
use DateTime;
use DateTimeZone;

class CrafyCAPTCHA
{

    private string $publicKey;
    private string $secretKey;
    private string $baseUrl;

    // Configuración del cliente HTTP
    private int $timeout = 10;

    // Configuración de Exponential Backoff
    private int $maxRetries = 3;
    private int $baseDelayMs = 500;
    private array $retryStatusCodes = [429, 500, 502, 503, 504];

    // Rutas de caché y nonces
    private string $cacheFile;
    private string $nonceDir;

    // Estado interno
    private ?string $accessToken = null;
    private ?string $lastFlowVerifyError = null;

    /**
     * Constructor
     * @param string $publicKey La llave pública (pk_...)
     * @param string $secretKey La llave secreta (sk_...)
     * @param string $baseUrl URL de la API (por defecto producción)
     */
    public function __construct(string $publicKey, string $secretKey, string $baseUrl = 'https://captcha.crafy.net/api')
    {
        $this->publicKey = $publicKey;
        $this->secretKey = $secretKey;
        $this->baseUrl = rtrim($baseUrl, '/');

        $this->setTempDir(sys_get_temp_dir());
    }

    /**
     * Establece el directorio temporal para guardar archivos de caché y nonces.
     */
    public function setTempDir(string $path): self
    {
        $hash = md5($this->publicKey . $this->secretKey);
        $this->cacheFile = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'crafy_token_' . $hash . '.json';
        
        $this->nonceDir = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'crafy_nonces';
        if (!is_dir($this->nonceDir)) {
            @mkdir($this->nonceDir, 0777, true);
        }
        return $this;
    }

    /**
     * Establece el número máximo de reintentos para peticiones HTTP fallidas.
     */
    public function setMaxRetries(int $retries): self
    {
        $this->maxRetries = max(0, $retries);
        return $this;
    }

    /**
     * Establece el tiempo base de espera (en milisegundos) para el Backoff Exponencial.
     */
    public function setBaseDelayMs(int $milliseconds): self
    {
        $this->baseDelayMs = max(0, $milliseconds);
        return $this;
    }

    /**
     * Establece los códigos HTTP que detonarán un reintento (Backoff).
     */
    public function setRetryStatusCodes(array $codes): self
    {
        $this->retryStatusCodes = $codes;
        return $this;
    }

    /**
     * Crea un nuevo Flow seguro para el cliente.
     * Genera un nonce criptográfico, lo guarda localmente y retorna las opciones encriptadas.
     * @param array $options Opciones de personalización del iframe.
     * @return string Opciones encriptadas (Ciphertext Base64).
     */
    public function createFlow(array $options = []): string
    {
        // 1. Generar Nonce criptográficamente seguro
        $nonce = bin2hex(random_bytes(32));

        // 2. Guardar el Nonce en archivo temporal (Lock file)
        $nonceFile = $this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_' . $nonce . '.lock';

        if (@file_put_contents($nonceFile, (string) time()) === false) {
            throw new Exception("CrafyCAPTCHA: No se pudo escribir el archivo nonce temporal.");
        }

        // 3. Preparar las opciones e inyectar el nonce
        $flowData = array_merge($options, ['nonce' => $nonce]);
        $jsonOptions = json_encode($flowData);

        // 4. Encriptar usando la clase anónima
        return $this->getCryptor()->encrypt($jsonOptions);
    }

    /**
     * Verifica un Flow completado sin llamar a la API externa.
     * Valida firma HMAC, expiración y consume el Nonce (Anti-Replay).
     * @param string $base64Payload El string base64 recibido del frontend.
     * @return bool True si el desafío es válido y seguro.
     */
    public function verifyFlow(string $base64Payload): bool
    {
        if (empty($base64Payload)) {
            $this->lastFlowVerifyError = 'El token está vacío.';
            return false;
        }

        // 1. Decodificar el sobre
        $jsonEnvelope = base64_decode($base64Payload);
        if (!$jsonEnvelope) {
            $this->lastFlowVerifyError = 'No se pudo decodificar el token.';
            return false;
        }

        $envelope = json_decode($jsonEnvelope, true);
        if (!isset($envelope['payload'], $envelope['server_sign'])) {
            $this->lastFlowVerifyError = 'Token malformado.';
            return false;
        }

        $payloadJson = $envelope['payload'];
        $signature = $envelope['server_sign'];

        // 2. Validar Firma (HMAC SHA256)
        $expectedSignature = hash_hmac('sha256', $payloadJson, $this->secretKey);

        if (!hash_equals($expectedSignature, $signature)) {
            $this->lastFlowVerifyError = 'Firma de seguridad inválida.';
            return false;
        }

        // 3. Decodificar Payload Interno
        $data = json_decode($payloadJson, true);
        if (!$data) {
            $this->lastFlowVerifyError = 'No se pudo decodificar el payload interno.';
            return false;
        }

        // 4. Validar Estado
        if (!isset($data['status']) || $data['status'] !== 'success') {
            $this->lastFlowVerifyError = 'Estado de Flow inválido.';
            return false;
        }

        // 5. Validar Expiración (UTC)
        if (!isset($data['expires_at'])) {
            $this->lastFlowVerifyError = 'Fecha de expiración no definida.';
            return false;
        }

        try {
            $expiresAt = new DateTime($data['expires_at'], new DateTimeZone('UTC'));
            $now = new DateTime('now', new DateTimeZone('UTC'));

            if ($now > $expiresAt) {
                $this->lastFlowVerifyError = 'Token expirado.';
                return false;
            }
        } catch (Exception $e) {
            $this->lastFlowVerifyError = 'Fecha de expiración inválida.';
            return false;
        }

        // 6. Validar Nonce (Protección Anti-Replay)
        if (!isset($data['nonce'])) {
            $this->lastFlowVerifyError = 'Nonce no encontrado.';
            return false;
        }

        $decryptedNonce = $this->getCryptor()->decrypt($data['nonce']);

        if (!isset($decryptedNonce) || !$decryptedNonce) {
            $this->lastFlowVerifyError = 'No se pudo decodificar el nonce.';
            return false;
        }

        $cleanNonce = preg_replace('/[^a-f0-9]/', '', $decryptedNonce);
        if ($cleanNonce !== $decryptedNonce) {
            $this->lastFlowVerifyError = 'Nonce inválido.';
            return false;
        }

        $nonceFile = $this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_' . $cleanNonce . '.lock';

        // Intento de borrado atómico
        if (!@unlink($nonceFile)) {
            $this->lastFlowVerifyError = 'Nonce ya utilizado (Replay Attack).';
            return false;
        }

        // 7. Garbage Collection: siempre si >50 archivos, o 1/100 aleatorio
        $nonceFiles = glob($this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_*.lock');
        if ($nonceFiles !== false && count($nonceFiles) > 50) {
            $this->garbageCollectNonces($nonceFiles);
        } elseif (rand(1, 100) === 1) {
            $this->garbageCollectNonces();
        }

        return true;
    }

    /**
     * Obtiene el último error ocurrido durante la verificación de un Flow.
     * @return string|null El mensaje de error o null si la verificación fue exitosa.
     */
    public function getLastFlowVerifyError(): ?string
    {
        return $this->lastFlowVerifyError;
    }

    /**
     * Limpia nonces viejos que nunca fueron usados.
     * @param array|null $files Lista de archivos pre-cargada (para evitar doble glob).
     */
    private function garbageCollectNonces(?array $files = null): void
    {
        if ($files === null) {
            $files = glob($this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_*.lock');
        }
        if ($files === false) return;
        
        $now = time();
        foreach ($files as $file) {
            if (is_file($file) && ($now - filemtime($file) > 1200)) { // 20 min TTL
                @unlink($file);
            }
        }
    }

    /**
     * Elimina TODOS los archivos nonce de forma inmediata.
     * Útil para mantenimiento o limpieza manual.
     * @return int Número de archivos eliminados.
     */
    public function clearAllNonces(): int
    {
        $files = glob($this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_*.lock');
        if ($files === false) return 0;
        
        $count = 0;
        foreach ($files as $file) {
            if (is_file($file) && @unlink($file)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Realiza una llamada a la API gestionando la autenticación automáticamente.
     */
    public function call(string $action, array $data = []): array
    {
        $this->ensureAuth();

        try {
            return $this->sendRequest($action, $data, true);
        } catch (Exception $e) {
            if ($e->getCode() === 401) {
                $this->clearCache();
                $this->ensureAuth(true);
                return $this->sendRequest($action, $data, true);
            }
            throw $e;
        }
    }

    private function ensureAuth(bool $forceRefresh = false): void
    {
        if (!$forceRefresh && $this->accessToken)
            return;

        if (!$forceRefresh && file_exists($this->cacheFile)) {
            $cached = json_decode(@file_get_contents($this->cacheFile), true);
            if (isset($cached['token'], $cached['expires_at']) && time() < ($cached['expires_at'] - 60)) {
                $this->accessToken = $cached['token'];
                return;
            }
        }

        $authPayload = ['public_key' => $this->publicKey, 'secret_key' => $this->secretKey];
        $response = $this->sendRequest('authenticate', $authPayload, false);

        if (empty($response['token'])) {
            throw new Exception("CrafyCAPTCHA SDK: No se recibió token de autenticación.");
        }

        $this->accessToken = $response['token'];
        $expiresIn = (int) ($response['expires_in'] ?? 3600);
        $this->saveCache($this->accessToken, time() + $expiresIn);
    }

    private function saveCache(string $token, int $expiresAt): void
    {
        $data = json_encode(['token' => $token, 'expires_at' => $expiresAt]);
        if (@file_put_contents($this->cacheFile, $data, LOCK_EX) !== false) {
            @chmod($this->cacheFile, 0600);
        }
    }

    private function clearCache(): void
    {
        $this->accessToken = null;
        if (file_exists($this->cacheFile)) {
            @unlink($this->cacheFile);
        }
    }

    private function sendRequest(string $action, array $data, bool $useAuth): array
    {
        $url = $this->baseUrl . '/?action=' . urlencode($action);
        
        $headers = [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: CrafyCAPTCHA-PHP-SDK/2.2'
        ];

        if ($useAuth && $this->accessToken) {
            $headers[] = 'Authorization: Bearer ' . $this->accessToken;
        }

        $attempt = 0;
        $maxAttempts = $this->maxRetries + 1;

        while ($attempt < $maxAttempts) {
            $ch = curl_init($url);
            if (!$ch) {
                throw new Exception("CrafyCAPTCHA: Fallo al inicializar cURL.");
            }

            $responseHeaders = [];
            
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($data),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_HEADERFUNCTION => function($curl, $header) use (&$responseHeaders) {
                    $len = strlen($header);
                    $parts = explode(':', $header, 2);
                    if (count($parts) >= 2) {
                        $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                    return $len;
                }
            ]);

            $resultRaw = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);

            $attempt++;

            // Evaluar si debemos reintentar (Backoff)
            $shouldRetry = false;
            if (!$curlError && in_array($httpCode, $this->retryStatusCodes)) {
                $shouldRetry = true;
            }

            if ($shouldRetry && $attempt < $maxAttempts) {
                // Respetar Retry-After si existe
                $delayUs = 0;
                if (isset($responseHeaders['retry-after'])) {
                    $retryAfter = $responseHeaders['retry-after'];
                    if (is_numeric($retryAfter)) {
                        $delayUs = (int)$retryAfter * 1000000;
                    } else {
                        $time = strtotime($retryAfter);
                        if ($time !== false && $time > time()) {
                            $delayUs = ($time - time()) * 1000000;
                        }
                    }
                }

                // Fallback a Exponential Backoff
                if ($delayUs <= 0) {
                    $delayUs = ($this->baseDelayMs * 1000) * pow(2, $attempt - 1);
                }

                usleep($delayUs);
                continue;
            }

            // Manejo de respuesta final tras reintentos agotados
            if ($curlError) {
                throw new Exception("CrafyCAPTCHA Network Error: $curlError");
            }

            if ($httpCode === 401) {
                throw new Exception("Unauthorized", 401); // Para que el método call() lo capture
            }

            $response = json_decode((string)$resultRaw, true);

            // Evitar crash si es un error HTML (ej. Cloudflare 500)
            if (json_last_error() !== JSON_ERROR_NONE) {
                if ($httpCode >= 400) {
                    throw new Exception("CrafyCAPTCHA HTTP Error ($httpCode)", $httpCode);
                }
                throw new Exception("CrafyCAPTCHA API Error: Respuesta inválida. HTTP Code: $httpCode");
            }

            if (isset($response['status']) && $response['status'] === 'error') {
                $msg = $response['message'] ?? 'Error desconocido';
                throw new Exception($msg, $httpCode);
            }

            if ($httpCode >= 400) {
                throw new Exception("CrafyCAPTCHA HTTP Error ($httpCode)", $httpCode);
            }

            return $response['data'] ?? [];
        }

        throw new Exception("CrafyCAPTCHA: Max retries exceeded.");
    }

    /**
     * Retorna una instancia de la clase anónima de encriptación.
     * Esta clase anónima encapsula toda la lógica de BitBookLiteCryptor.
     * * @return object Clase anónima con métodos encrypt() y decrypt()
     */
    private function getCryptor()
    {
        return new class ($this->secretKey) {

            private const ENCRYPTION_ALGORITHM = 'AES-256-CBC';
            private const HASHING_ALGORITHM = 'sha256';

            // Constantes Sodium
            private const SALT_LEN = 16;  // SODIUM_CRYPTO_PWHASH_SALTBYTES
            private const KEY_LEN = 32;  // SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES
            private const NONCE_LEN = 24;  // SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES

            private string $secret;
            private $v3Key;
            private $v1Key;

            public function __construct(string $secret)
            {
                if ($secret === '')
                    throw new \InvalidArgumentException('Secret no puede ser vacío.');
                $this->secret = $secret;
                
                if (function_exists('sodium_crypto_generichash')) {
                    $this->v3Key = sodium_crypto_generichash($secret, '', self::KEY_LEN);
                }
                
                $this->v1Key = hash(self::HASHING_ALGORITHM, $secret, true);
            }

            public function encrypt(string $plaintext, int $version = 3): string
            {
                if ($version == 3 && function_exists('sodium_crypto_generichash')) {
                    $nonce = random_bytes(self::NONCE_LEN);

                    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                        $plaintext,
                        '', 
                        $nonce,
                        $this->v3Key
                    );

                    return ';v3_;' . base64_encode($nonce . $ciphertext);
                    
                } elseif ($version == 2 && function_exists('sodium_crypto_pwhash')) {
                    $salt = random_bytes(self::SALT_LEN);

                    // Derivación de clave
                    $key = sodium_crypto_pwhash(
                        self::KEY_LEN,
                        $this->secret,
                        $salt,
                        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
                    );

                    $nonce = random_bytes(self::NONCE_LEN);

                    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                        $plaintext,
                        '',
                        $nonce,
                        $key
                    );

                    sodium_memzero($key);

                    $out = $salt . $nonce . $ciphertext;
                    return ';v2_;' . base64_encode($out);
                } else {
                    $iv = random_bytes(16);

                    $cipherText = openssl_encrypt(
                        $plaintext,
                        self::ENCRYPTION_ALGORITHM,
                        $this->v1Key,
                        OPENSSL_RAW_DATA,
                        $iv
                    );
                    $hash = hash_hmac(self::HASHING_ALGORITHM, $cipherText, $this->v1Key, true);

                    return bin2hex($iv . $hash . $cipherText);
                }
            }

            public function decrypt(string $input): ?string
            {
                $first_chars = substr($input, 0, 5);

                if ($first_chars === ';v3_;' && function_exists('sodium_crypto_generichash')) {
                    $input = substr($input, 5);
                    $decoded = base64_decode($input, true);
                    
                    if ($decoded === false || strlen($decoded) < self::NONCE_LEN) {
                        return null;
                    }

                    $nonce = substr($decoded, 0, self::NONCE_LEN);
                    $ciphertext = substr($decoded, self::NONCE_LEN);

                    $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                        $ciphertext,
                        '',
                        $nonce,
                        $this->v3Key
                    );

                    return $plaintext === false ? null : $plaintext;

                } elseif ($first_chars === ';v2_;' && function_exists('sodium_crypto_pwhash')) {
                    $input = substr($input, 5);
                    $decoded = base64_decode($input, true);

                    if ($decoded === false)
                        return null;
                    if (strlen($decoded) < (self::SALT_LEN + self::NONCE_LEN + 1))
                        return null;

                    $salt = substr($decoded, 0, self::SALT_LEN);
                    $nonce = substr($decoded, self::SALT_LEN, self::NONCE_LEN);
                    $ciphertext = substr($decoded, self::SALT_LEN + self::NONCE_LEN);

                    $key = sodium_crypto_pwhash(
                        self::KEY_LEN,
                        $this->secret,
                        $salt,
                        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
                    );

                    $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                        $ciphertext,
                        '',
                        $nonce,
                        $key
                    );

                    sodium_memzero($key);
                    return $plaintext === false ? null : $plaintext;
                } else {
                    if (strlen($input) % 2 !== 0 || !ctype_xdigit($input))
                        return null;

                    $binaryInput = hex2bin($input);
                    if (strlen($binaryInput) < 48) {
                        return null;
                    }

                    $iv = substr($binaryInput, 0, 16);
                    $hash = substr($binaryInput, 16, 32);
                    $cipherText = substr($binaryInput, 48);
                    
                    $calculatedHash = hash_hmac(self::HASHING_ALGORITHM, $cipherText, $this->v1Key, true);

                    if (!hash_equals($hash, $calculatedHash)) {
                        return null;
                    }

                    $plaintext = openssl_decrypt(
                        $cipherText,
                        self::ENCRYPTION_ALGORITHM,
                        $this->v1Key,
                        OPENSSL_RAW_DATA,
                        $iv
                    );
                    
                    return $plaintext === false ? null : $plaintext;
                }
            }
            
            public function __destruct()
            {
                if (function_exists('sodium_memzero') && isset($this->v3Key)) {
                    sodium_memzero($this->v3Key);
                }
            }
        };
    }
}