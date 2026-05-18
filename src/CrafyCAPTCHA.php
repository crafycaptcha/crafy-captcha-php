<?php

namespace Crafy\Captcha;

use Exception;
use DateTime;
use DateTimeZone;
use PDO;
use PDOException;

/**
 * Interfaz unificada para el almacenamiento de Caché y Nonces.
 */
interface StorageInterface
{
    /**
     * Obtiene un valor de caché por su clave.
     * @param string $key Clave identificadora del recurso en caché.
     * @return string|null Contenido almacenado o null si no existe.
     */
    public function getCache(string $key): ?string;

    /**
     * Almacena un valor en caché con tiempo de expiración.
     * @param string $key Clave identificadora.
     * @param string $data Datos a almacenar (ya encriptados).
     * @param int $expiresAt Timestamp UNIX de expiración.
     */
    public function setCache(string $key, string $data, int $expiresAt): void;

    /**
     * Elimina un valor de caché por su clave.
     * @param string $key Clave identificadora del recurso a eliminar.
     */
    public function deleteCache(string $key): void;

    /**
     * Almacena un nonce temporal para validación Anti-Replay.
     * @param string $nonce Nonce criptográfico (hex).
     * @param int $expiresAt Timestamp UNIX de expiración.
     */
    public function storeNonce(string $nonce, int $expiresAt): void;

    /**
     * Consume (valida y elimina) un nonce de forma atómica.
     * Solo el primer consumo retorna true; llamadas posteriores retornan false.
     * @param string $nonce Nonce a consumir.
     * @return bool True si el nonce existía y fue consumido exitosamente.
     */
    public function consumeNonce(string $nonce): bool;

    /**
     * Elimina TODOS los nonces almacenados de forma inmediata.
     * Útil para mantenimiento o limpieza manual.
     * @return int Número de nonces eliminados.
     */
    public function clearAllNonces(): int;

    /**
     * Ejecuta Garbage Collection para limpiar nonces expirados.
     * La implementación puede usar lógica probabilística para reducir overhead.
     */
    public function gcNonces(): void;
}

/**
 * Almacenamiento por defecto utilizando archivos temporales del sistema.
 */
class FileStorage implements StorageInterface
{
    private string $cacheDir;
    private string $nonceDir;

    /**
     * Constructor del almacenamiento basado en archivos.
     * @param string $tempDir Directorio base para archivos de caché y nonces.
     */
    public function __construct(string $tempDir)
    {
        $this->cacheDir = $tempDir;
        $this->nonceDir = rtrim($tempDir, '/\\') . DIRECTORY_SEPARATOR . 'crafy_nonces';
        if (!is_dir($this->nonceDir)) {
            @mkdir($this->nonceDir, 0777, true);
        }
    }

    /** {@inheritdoc} */
    public function getCache(string $key): ?string
    {
        $file = $this->cacheDir . DIRECTORY_SEPARATOR . $key . '.json';
        if (file_exists($file)) {
            return @file_get_contents($file) ?: null;
        }
        return null;
    }

    /** {@inheritdoc} */
    public function setCache(string $key, string $data, int $expiresAt): void
    {
        $file = $this->cacheDir . DIRECTORY_SEPARATOR . $key . '.json';
        if (@file_put_contents($file, $data, LOCK_EX) !== false) {
            @chmod($file, 0600);
        }
    }

    /** {@inheritdoc} */
    public function deleteCache(string $key): void
    {
        $file = $this->cacheDir . DIRECTORY_SEPARATOR . $key . '.json';
        if (file_exists($file)) {
            @unlink($file);
        }
    }

    /** {@inheritdoc} */
    public function storeNonce(string $nonce, int $expiresAt): void
    {
        $file = $this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_' . $nonce . '.lock';
        @file_put_contents($file, (string) $expiresAt, LOCK_EX);
    }

    /** {@inheritdoc} Utiliza unlink() atómico: solo un proceso puede borrar el archivo. */
    public function consumeNonce(string $nonce): bool
    {
        $file = $this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_' . $nonce . '.lock';
        if (file_exists($file)) {
            // unlink() es atómico y devolverá true solo si este proceso logró borrarlo
            return @unlink($file);
        }
        return false;
    }

    /** {@inheritdoc} */
    public function clearAllNonces(): int
    {
        $files = glob($this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_*.lock');
        $count = 0;
        if (is_array($files)) {
            foreach ($files as $file) {
                if (@unlink($file))
                    $count++;
            }
        }
        return $count;
    }

    /** {@inheritdoc} Limpia si hay >50 archivos o con probabilidad 1/100. TTL: 20 min. */
    public function gcNonces(): void
    {
        $files = glob($this->nonceDir . DIRECTORY_SEPARATOR . 'nonce_*.lock');
        if (is_array($files)) {
            // Limpieza si hay muchos archivos o con probabilidad aleatoria baja
            if (count($files) > 50 || random_int(1, 100) === 1) {
                $now = time();
                foreach ($files as $file) {
                    if (is_file($file) && filemtime($file) < ($now - 1200)) { // 20 min TTL
                        @unlink($file);
                    }
                }
            }
        }
    }
}

/**
 * Almacenamiento opcional en base de datos SQL (MySQL/MariaDB, PostgreSQL, SQLite).
 */
class PDOStorage implements StorageInterface
{
    private PDO $pdo;
    private string $tableName;

    /**
     * Constructor del almacenamiento basado en base de datos.
     * Crea la tabla automáticamente si no existe.
     * @param PDO $pdo Instancia de PDO conectada (MySQL/MariaDB, PostgreSQL, SQLite).
     * @param string $tableName Nombre de la tabla de almacenamiento.
     */
    public function __construct(PDO $pdo, string $tableName = 'crafy_storage')
    {
        $this->pdo = $pdo;
        $this->tableName = $tableName;
        $this->initTable();
    }

    /**
     * Crea la tabla de almacenamiento si no existe.
     */
    private function initTable(): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS {$this->tableName} (
            id VARCHAR(128) PRIMARY KEY,
            type VARCHAR(16) NOT NULL,
            data TEXT NULL,
            expires_at INT NOT NULL
        )";
        $this->pdo->exec($sql);
    }

    /** {@inheritdoc} */
    public function getCache(string $key): ?string
    {
        $stmt = $this->pdo->prepare("SELECT data FROM {$this->tableName} WHERE id = ? AND type = 'cache' AND expires_at > ?");
        $stmt->execute([$key, time()]);
        $result = $stmt->fetchColumn();
        return $result !== false ? (string) $result : null;
    }

    /** {@inheritdoc} */
    public function setCache(string $key, string $data, int $expiresAt): void
    {
        $this->deleteCache($key);
        $stmt = $this->pdo->prepare("INSERT INTO {$this->tableName} (id, type, data, expires_at) VALUES (?, 'cache', ?, ?)");
        $stmt->execute([$key, $data, $expiresAt]);
    }

    /** {@inheritdoc} */
    public function deleteCache(string $key): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE id = ? AND type = 'cache'");
        $stmt->execute([$key]);
    }

    /** {@inheritdoc} Ignora duplicados silenciosamente. */
    public function storeNonce(string $nonce, int $expiresAt): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO {$this->tableName} (id, type, data, expires_at) VALUES (?, 'nonce', '', ?)");
        try {
            $stmt->execute([$nonce, $expiresAt]);
        } catch (PDOException $e) {
            // Ignorar duplicados
        }
    }

    /** {@inheritdoc} Usa DELETE atómico: solo un request concurrente puede afectar la fila. */
    public function consumeNonce(string $nonce): bool
    {
        // El DELETE atómico asegura que si hay requests concurrentes, solo uno afectará la fila y devolverá true
        $stmt = $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE id = ? AND type = 'nonce' AND expires_at > ?");
        $stmt->execute([$nonce, time()]);
        return $stmt->rowCount() > 0;
    }

    /** {@inheritdoc} */
    public function clearAllNonces(): int
    {
        $stmt = $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE type = 'nonce'");
        $stmt->execute();
        return $stmt->rowCount();
    }

    /** {@inheritdoc} Ejecuta con probabilidad 1/100. Limpia cache y nonces expirados. */
    public function gcNonces(): void
    {
        if (random_int(1, 100) === 1) {
            $stmt = $this->pdo->prepare("DELETE FROM {$this->tableName} WHERE expires_at <= ?");
            $stmt->execute([time()]);
        }
    }
}

/**
 * Cliente Principal SDK CrafyCAPTCHA
 */
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

    // Motor de Almacenamiento
    private StorageInterface $storage;

    // Estado interno
    private ?string $accessToken = null;
    private ?string $lastFlowVerifyError = null;
    private ?string $publicToken = null;

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

        // Por defecto, inicializamos el almacenamiento basado en archivos
        $this->storage = new FileStorage(sys_get_temp_dir());
    }

    /**
     * Inyecta un sistema de almacenamiento personalizado (PDO, Redis, Memcached, etc.)
     */
    public function setStorage(StorageInterface $storage): self
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * @deprecated Usa setStorage(new FileStorage($path))
     */
    public function setTempDir(string $path): self
    {
        $this->storage = new FileStorage($path);
        return $this;
    }

    /**
     * Establece el número máximo de reintentos para peticiones HTTP fallidas.
     * @param int $retries Número de reintentos (mínimo 0).
     * @return self
     */
    public function setMaxRetries(int $retries): self
    {
        $this->maxRetries = max(0, $retries);
        return $this;
    }

    /**
     * Establece el tiempo base de espera (en milisegundos) para el Backoff Exponencial.
     * @param int $milliseconds Tiempo base en ms (mínimo 0).
     * @return self
     */
    public function setBaseDelayMs(int $milliseconds): self
    {
        $this->baseDelayMs = max(0, $milliseconds);
        return $this;
    }

    /**
     * Establece los códigos HTTP que detonarán un reintento (Backoff).
     * @param array $codes Lista de códigos HTTP (ej: [429, 500, 502, 503, 504]).
     * @return self
     */
    public function setRetryStatusCodes(array $codes): self
    {
        $this->retryStatusCodes = $codes;
        return $this;
    }

    /**
     * Genera la clave única de caché basada en las credenciales.
     * @return string Clave de caché derivada de public+secret key.
     */
    private function getCacheKey(): string
    {
        return 'crafy_token_' . md5($this->publicKey . $this->secretKey);
    }

    /**
     * Obtiene el Public Token dinámicamente.
     * Si no está en memoria o caché, dispara la autenticación.
     * @return string Public Token para uso en el frontend.
     */
    public function getPublicToken(): string
    {
        $this->ensureAuth();
        return $this->publicToken;
    }

    /**
     * Crea un nuevo Flow seguro para el cliente.
     * Genera un nonce criptográfico, lo guarda localmente y retorna las opciones encriptadas.
     * @param array $options Opciones de personalización del iframe.
     * @return string Opciones encriptadas (Ciphertext Base64).
     */
    public function createFlow(array $options = []): string
    {
        $nonce = bin2hex(random_bytes(32));

        // Almacenar el nonce temporal con un TTL de 20 minutos (1200 seg)
        $this->storage->storeNonce($nonce, time() + 1200);

        $flowData = $options;
        $flowData['nonce'] = $nonce;
        $jsonOptions = json_encode($flowData);

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
        $this->lastFlowVerifyError = null;

        if (empty($base64Payload)) {
            $this->lastFlowVerifyError = 'El token está vacío.';
            return false;
        }

        $jsonEnvelope = base64_decode($base64Payload);
        $envelope = json_decode($jsonEnvelope, true);

        if (!$envelope || empty($envelope['payload']) || empty($envelope['server_sign'])) {
            $this->lastFlowVerifyError = 'Token malformado.';
            return false;
        }

        $payloadJson = $envelope['payload'];
        $signature = $envelope['server_sign'];

        $expectedSignature = hash_hmac('sha256', $payloadJson, $this->secretKey);

        if (!hash_equals($expectedSignature, $signature)) {
            $this->lastFlowVerifyError = 'Firma de seguridad inválida.';
            return false;
        }

        $data = json_decode($payloadJson, true);
        if (!$data) {
            $this->lastFlowVerifyError = 'No se pudo decodificar el payload interno.';
            return false;
        }

        if (($data['status'] ?? '') !== 'success') {
            $this->lastFlowVerifyError = 'Estado de Flow inválido.';
            return false;
        }

        if (empty($data['expires_at'])) {
            $this->lastFlowVerifyError = 'Fecha de expiración no definida.';
            return false;
        }

        try {
            $cleanDate = str_replace('Z', '+00:00', $data['expires_at']);
            $expiresAt = new DateTime($cleanDate);
            if (!$expiresAt->getTimezone() || $expiresAt->getTimezone()->getName() === 'Z') {
                $expiresAt->setTimezone(new DateTimeZone('UTC'));
            }

            $now = new DateTime('now', new DateTimeZone('UTC'));

            if ($now > $expiresAt) {
                $this->lastFlowVerifyError = 'Token expirado.';
                return false;
            }
        } catch (Exception $e) {
            $this->lastFlowVerifyError = 'Fecha de expiración inválida.';
            return false;
        }

        if (empty($data['nonce'])) {
            $this->lastFlowVerifyError = 'Nonce no encontrado.';
            return false;
        }

        $decryptedNonce = $this->getCryptor()->decrypt($data['nonce']);

        if (!$decryptedNonce) {
            $this->lastFlowVerifyError = 'No se pudo decodificar el nonce.';
            return false;
        }

        $cleanNonce = preg_replace('/[^a-f0-9]/', '', $decryptedNonce);
        if ($cleanNonce !== $decryptedNonce) {
            $this->lastFlowVerifyError = 'Nonce inválido.';
            return false;
        }

        // Intento atómico de validación y borrado (Anti-Replay)
        if (!$this->storage->consumeNonce($cleanNonce)) {
            $this->lastFlowVerifyError = 'Nonce ya utilizado (Replay Attack) o expirado.';
            return false;
        }

        // Garbage Collection
        $this->storage->gcNonces();

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
     * Elimina TODOS los nonces almacenados de forma inmediata.
     * Útil para mantenimiento o limpieza manual.
     * @return int Número de nonces eliminados.
     */
    public function clearAllNonces(): int
    {
        return $this->storage->clearAllNonces();
    }

    /**
     * Realiza una llamada a la API gestionando la autenticación automáticamente.
     * Si recibe un 401, refresca las credenciales y reintenta.
     * @param string $action Nombre de la acción de la API.
     * @param array $data Datos a enviar en el body de la petición.
     * @return array Datos de respuesta de la API.
     * @throws Exception En caso de error de red, autenticación o API.
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

    /**
     * Asegura que el SDK esté autenticado.
     * Busca primero en memoria, luego en caché encriptada, y si no, autentica contra la API.
     * @param bool $forceRefresh Si es true, ignora caché y fuerza re-autenticación.
     */
    private function ensureAuth(bool $forceRefresh = false): void
    {
        if (!$forceRefresh && $this->accessToken && $this->publicToken)
            return;

        if (!$forceRefresh) {
            $rawContent = $this->storage->getCache($this->getCacheKey());

            if ($rawContent) {
                $decrypted = $this->getCryptor()->decrypt($rawContent);
                $cached = $decrypted ? json_decode($decrypted, true) : null;

                if (isset($cached['token'], $cached['public_token'], $cached['expires_at'])) {
                    if (time() < ($cached['expires_at'] - 60)) {
                        $this->accessToken = $cached['token'];
                        $this->publicToken = $cached['public_token'];
                        return;
                    }
                }
            }
        }

        $authPayload = ['public_key' => $this->publicKey, 'secret_key' => $this->secretKey];
        $response = $this->sendRequest('authenticate', $authPayload, false);

        if (empty($response['token']) || empty($response['public_token'])) {
            throw new Exception("CrafyCAPTCHA SDK: Error en la respuesta de autenticación.");
        }

        $this->accessToken = $response['token'];
        $this->publicToken = $response['public_token'];

        $expiresIn = (int) ($response['expires_in'] ?? 86400);
        $this->saveCache($this->accessToken, $this->publicToken, time() + $expiresIn);
    }

    /**
     * Guarda los tokens de autenticación en caché encriptada.
     * @param string $token Access Token de la API.
     * @param string $publicToken Public Token para el frontend.
     * @param int $expiresAt Timestamp UNIX de expiración.
     */
    private function saveCache(string $token, string $publicToken, int $expiresAt): void
    {
        $data = json_encode([
            'token' => $token,
            'public_token' => $publicToken,
            'expires_at' => $expiresAt
        ]);

        $encryptedData = $this->getCryptor()->encrypt($data);
        $this->storage->setCache($this->getCacheKey(), $encryptedData, $expiresAt);
    }

    /**
     * Limpia los tokens de memoria y elimina la caché persistida.
     */
    private function clearCache(): void
    {
        $this->accessToken = null;
        $this->publicToken = null;
        $this->storage->deleteCache($this->getCacheKey());
    }

    /**
     * Envía una petición HTTP POST a la API con soporte de Exponential Backoff.
     * Respeta el header Retry-After si está presente.
     * @param string $action Acción de la API.
     * @param array $data Datos del body.
     * @param bool $useAuth Si es true, incluye el header Authorization Bearer.
     * @return array Datos de respuesta.
     * @throws Exception En caso de error de red, HTTP o API.
     */
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
            $attempt++;

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
            curl_setopt($ch, CURLOPT_HEADER, true);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $curlError = curl_error($ch);
            curl_close($ch);

            if ($response === false) {
                if ($attempt >= $maxAttempts) {
                    throw new Exception("CrafyCAPTCHA Network Error: " . $curlError);
                }
                $delayUs = (int) (($this->baseDelayMs * 1000) * pow(2, $attempt - 1));
                usleep($delayUs);
                continue;
            }

            $rawHeaders = substr($response, 0, $headerSize);
            $body = substr($response, $headerSize);

            $shouldRetry = in_array($httpCode, $this->retryStatusCodes);

            if ($shouldRetry && $attempt < $maxAttempts) {
                $delayUs = 0;
                if (preg_match('/Retry-After:\s*([^\r\n]+)/i', $rawHeaders, $matches)) {
                    $retryAfter = trim($matches[1]);
                    if (is_numeric($retryAfter)) {
                        $delayUs = (int) $retryAfter * 1000000;
                    } else {
                        $time = strtotime($retryAfter);
                        if ($time !== false && $time > time()) {
                            $delayUs = ($time - time()) * 1000000;
                        }
                    }
                }

                if ($delayUs <= 0) {
                    $delayUs = (int) (($this->baseDelayMs * 1000) * pow(2, $attempt - 1));
                }

                usleep($delayUs);
                continue;
            }

            if ($httpCode === 401) {
                throw new Exception("Unauthorized", 401);
            }

            $jsonResp = json_decode($body, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                if ($httpCode >= 400) {
                    throw new Exception("CrafyCAPTCHA HTTP Error ($httpCode)", $httpCode);
                }
                throw new Exception("CrafyCAPTCHA API Error: Respuesta inválida. HTTP Code: $httpCode");
            }

            if (($jsonResp['status'] ?? '') === 'error') {
                $msg = $jsonResp['message'] ?? 'Error desconocido';
                throw new Exception($msg, $httpCode);
            }

            if ($httpCode >= 400) {
                throw new Exception("CrafyCAPTCHA HTTP Error ($httpCode)", $httpCode);
            }

            return $jsonResp['data'] ?? [];
        }

        throw new Exception("CrafyCAPTCHA: Max retries exceeded.");
    }

    /**
     * Retorna una instancia de la clase anónima de encriptación.
     * Soporta 3 versiones: v3 (XChaCha20-Poly1305), v2 (Sodium pwhash), v1 (AES-256-CBC + HMAC).
     * @return object Clase anónima con métodos encrypt() y decrypt().
     */
    private function getCryptor(): object
    {
        return clone new class ($this->secretKey) {
            private const ENCRYPTION_ALGORITHM = 'AES-256-CBC';
            private const HASHING_ALGORITHM = 'sha256';

            private string $secretKey;
            private string $v1Key;
            private string $v3Key;

            public function __construct(string $secretKey)
            {
                $this->secretKey = $secretKey;
                $this->v1Key = hash('sha256', $this->secretKey, true);

                if (function_exists('sodium_crypto_generichash')) {
                    $this->v3Key = sodium_crypto_generichash($this->secretKey, '', 32);
                }
            }

            public function encrypt(string $plaintext, int $version = 3): string
            {
                if ($version === 3 && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
                    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
                    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $this->v3Key);
                    return ';v3_;' . base64_encode($nonce . $ciphertext);
                } elseif ($version === 2 && function_exists('sodium_crypto_pwhash')) {
                    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
                    $key = sodium_crypto_pwhash(
                        SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
                        $this->secretKey,
                        $salt,
                        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                        SODIUM_CRYPTO_PWHASH_ALG_DEFAULT
                    );

                    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
                    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $key);

                    sodium_memzero($key);
                    return ';v2_;' . base64_encode($salt . $nonce . $ciphertext);
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
                $firstChars = substr($input, 0, 5);

                if ($firstChars === ';v3_;' && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')) {
                    $decoded = base64_decode(substr($input, 5));
                    if (strlen($decoded) < SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
                        return null;

                    $nonce = substr($decoded, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
                    $ciphertext = substr($decoded, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

                    $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, '', $nonce, $this->v3Key);
                    return $plaintext === false ? null : $plaintext;
                } elseif ($firstChars === ';v2_;' && function_exists('sodium_crypto_pwhash')) {
                    $decoded = base64_decode(substr($input, 5));
                    $saltLen = SODIUM_CRYPTO_PWHASH_SALTBYTES;
                    $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

                    if (strlen($decoded) < ($saltLen + $nonceLen + 1))
                        return null;

                    $salt = substr($decoded, 0, $saltLen);
                    $nonce = substr($decoded, $saltLen, $nonceLen);
                    $ciphertext = substr($decoded, $saltLen + $nonceLen);

                    $key = sodium_crypto_pwhash(
                        SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
                        $this->secretKey,
                        $salt,
                        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                        SODIUM_CRYPTO_PWHASH_ALG_DEFAULT
                    );

                    $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, '', $nonce, $key);
                    sodium_memzero($key);
                    return $plaintext === false ? null : $plaintext;
                } else {
                    if (strlen($input) % 2 !== 0 || !ctype_xdigit($input))
                        return null;

                    $binaryInput = hex2bin($input);
                    if (strlen($binaryInput) < 48)
                        return null;

                    $iv = substr($binaryInput, 0, 16);
                    $hash = substr($binaryInput, 16, 32);
                    $cipherText = substr($binaryInput, 48);

                    $calculatedHash = hash_hmac(self::HASHING_ALGORITHM, $cipherText, $this->v1Key, true);

                    if (!hash_equals($hash, $calculatedHash))
                        return null;

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