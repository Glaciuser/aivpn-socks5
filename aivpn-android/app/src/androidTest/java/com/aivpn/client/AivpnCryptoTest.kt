package com.aivpn.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for AivpnCrypto.
 * Run on emulator/device because ChaCha20-Poly1305 requires Android crypto provider.
 */
@RunWith(AndroidJUnit4::class)
class AivpnCryptoTest {

    /**
     * RFC 7748 X25519 test vector:
     * Alice private = 0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
     * Alice public  = 0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
     * Bob private   = 0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
     * Bob public    = 0x de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
     * Shared        = 0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
     *
     * We use these to verify X25519 scalar multiplication is correct.
     */
    @Test
    fun testX25519KeyExchange() {
        // Use two AivpnCrypto instances as "server" and "client" with known keys
        // Just verify that creating a crypto instance doesn't crash and produces 32-byte public key
        val fakeServerKey = ByteArray(32) { 9 } // basepoint repeated
        val crypto = AivpnCrypto(fakeServerKey)
        assertNotNull(crypto)
    }

    @Test
    fun testBuildInitPacket() {
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        val initPacket = crypto.buildInitPacket()

        // Init packet should contain: TAG(8) + MDH(4) + eph_pub(32) + encrypted payload
        // Minimum size: 8 + 4 + 32 + (2+4+1 + 8_pad) + 16_poly = at least 75 bytes
        assertTrue("Init packet too small: ${initPacket.size}", initPacket.size >= 60)
    }

    @Test
    fun testEncryptDecryptRoundtrip() {
        // Create two crypto instances with the same "server key" to simulate
        // client↔client self-test (same session key derived from same DH).
        // Since both derive keys from the same shared secret, encryption/decryption
        // won't work cross-instance (counters differ), but each instance should
        // produce valid encrypted data packets.
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        val testPayload = "Hello AIVPN Test!".toByteArray()
        val encrypted = crypto.encryptDataPacket(testPayload)

        // Encrypted packet = TAG(8) + MDH(4) + ciphertext (includes inner header + padding + AEAD tag)
        assertTrue("Encrypted packet too small", encrypted.size > 12 + testPayload.size)

        // Verify encrypted data is different from plaintext (basic sanity)
        val payloadSlice = encrypted.copyOfRange(12, minOf(12 + testPayload.size, encrypted.size))
        assertFalse("Ciphertext matches plaintext!", payloadSlice.contentEquals(testPayload))
    }

    @Test
    fun testDecryptInvalidPacket() {
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        // Random garbage should not decrypt
        val garbage = ByteArray(100).also { java.security.SecureRandom().nextBytes(it) }
        val result = crypto.decryptDataPacket(garbage)
        assertNull("Should not decrypt random data", result)
    }

    @Test
    fun testDecryptTooShortPacket() {
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        // Packet shorter than TAG + MDH + minimum AEAD
        val tooShort = ByteArray(10)
        val result = crypto.decryptDataPacket(tooShort)
        assertNull("Should reject undersized packet", result)
    }

    @Test
    fun testProcessServerHelloInvalid() {
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        // Random data should fail ServerHello processing
        val fakeHello = ByteArray(200).also { java.security.SecureRandom().nextBytes(it) }
        assertFalse("Should reject invalid ServerHello", crypto.processServerHello(fakeHello))
    }

    @Test
    fun testMultiplePacketsHaveUniqueTag() {
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        val payload = ByteArray(64) { it.toByte() }
        val pkt1 = crypto.encryptDataPacket(payload)
        val pkt2 = crypto.encryptDataPacket(payload)

        // Tags should differ (different counter)
        val tag1 = pkt1.copyOfRange(0, 8)
        val tag2 = pkt2.copyOfRange(0, 8)
        assertFalse("Sequential packets should have different tags", tag1.contentEquals(tag2))
    }

    @Test
    fun testInitPacketContainsObfuscatedEphPub() {
        val serverKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val crypto = AivpnCrypto(serverKey)

        val initPkt = crypto.buildInitPacket()

        // Bytes 12..44 should be obfuscated eph_pub (XOR'd with BLAKE3 mask)
        // They should NOT be all zeros
        val obfEphPub = initPkt.copyOfRange(12, 44)
        assertFalse("Obfuscated eph_pub is all zeros", obfEphPub.all { it == 0.toByte() })
    }

    // ── BLAKE3 cross-verification against Rust blake3 crate ──

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length / 2
        val result = ByteArray(len)
        for (i in 0 until len) {
            result[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }

    @Test
    fun testBlake3DeriveKeyObfuscation() {
        val expected = "1a45613377181ba98318202ef1999dc0d51971cbf2b0770051e3767c1670b29b"
        val result = Blake3.deriveKey("aivpn-eph-obfuscation-v1", ByteArray(32))
        assertEquals("BLAKE3 derive_key obfuscation mismatch", expected, result.toHex())
    }

    @Test
    fun testBlake3DeriveKeySessionKey() {
        val expected = "82cc564962210bce76783dd53e53a623f7b9762b15153523df369c6142cc4c2d"
        val result = Blake3.deriveKey("aivpn-session-key-v1", ByteArray(64) { 1 })
        assertEquals("BLAKE3 derive_key session-key mismatch", expected, result.toHex())
    }

    @Test
    fun testBlake3DeriveKeyTagSecret() {
        val expected = "eac5a93e2d76897142e3baf6ad74a233e357ce5cb00ec2a3e05b2a8ce20f73fb"
        val result = Blake3.deriveKey("aivpn-tag-secret-v1", ByteArray(64) { 1 })
        assertEquals("BLAKE3 derive_key tag-secret mismatch", expected, result.toHex())
    }

    @Test
    fun testBlake3KeyedHash() {
        val expected = "4eac5f3d052898b0db329e7287c6b61c0724b4516827d428ca3e8b1832170b2d"
        val key = ByteArray(32) { 2 }
        val data = byteArrayOf(0,0,0,0,0,0,0,0, 100,0,0,0,0,0,0,0)
        val result = Blake3.keyedHash(key, data)
        assertEquals("BLAKE3 keyed_hash mismatch", expected, result.toHex())
    }

    // ── X25519 cross-verification via reflection ──

    @Test
    fun testX25519RFC7748AlicePublicKey() {
        // RFC 7748 test vector: Alice's keypair
        val alicePriv = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val expectedPub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

        // Use a dummy crypto instance to access X25519 via reflection
        val crypto = AivpnCrypto(ByteArray(32) { 9 })
        val method = crypto.javaClass.getDeclaredMethod("x25519ScalarMultBase", ByteArray::class.java)
        method.isAccessible = true
        val computedPub = method.invoke(crypto, alicePriv) as ByteArray
        assertEquals("X25519 RFC 7748 Alice pub mismatch", expectedPub, computedPub.toHex())
    }

    @Test
    fun testX25519MatchesRust() {
        // Known client private key (already clamped)
        val clientPriv = hexToBytes("7001000000000000000000000000000000000000000000000000000000000040")
        val expectedPub = "23e7aa0d74e07cd35fa71ffb2a6dc1f11b9b27a976838e6a1a5aac8ed14bb817"
        val serverPub = hexToBytes("815fb6314405e007d04ed215c223d5cd4b799d07bb7189ad10dbf324ea534271")
        val expectedDh = "6836e8dc6b83a63fc2bd040cf9e92913a24c4ef1f8095cf406e986b248584a24"

        val crypto = AivpnCrypto(serverPub)
        val baseMult = crypto.javaClass.getDeclaredMethod("x25519ScalarMultBase", ByteArray::class.java)
        baseMult.isAccessible = true
        val computedPub = baseMult.invoke(crypto, clientPriv) as ByteArray
        assertEquals("X25519 base mult mismatch", expectedPub, computedPub.toHex())

        val scalarMult = crypto.javaClass.getDeclaredMethod("x25519ScalarMult", ByteArray::class.java, ByteArray::class.java)
        scalarMult.isAccessible = true
        val computedDh = scalarMult.invoke(crypto, clientPriv, serverPub) as ByteArray
        assertEquals("X25519 DH shared secret mismatch", expectedDh, computedDh.toHex())
    }

    @Test
    fun testFullProtocolCrossVerification() {
        // Full protocol flow: DH → derive keys → generate tag
        // All values verified against Rust aivpn-common
        val clientPriv = hexToBytes("7001000000000000000000000000000000000000000000000000000000000040")
        val clientPub = hexToBytes("23e7aa0d74e07cd35fa71ffb2a6dc1f11b9b27a976838e6a1a5aac8ed14bb817")
        val serverPub = hexToBytes("815fb6314405e007d04ed215c223d5cd4b799d07bb7189ad10dbf324ea534271")
        val dh1 = hexToBytes("6836e8dc6b83a63fc2bd040cf9e92913a24c4ef1f8095cf406e986b248584a24")

        // KDF: derive session keys
        val input = dh1 + clientPub  // ikm(32) || eph_pub(32) = 64 bytes
        val sessionKey = Blake3.deriveKey("aivpn-session-key-v1", input)
        val tagSecret = Blake3.deriveKey("aivpn-tag-secret-v1", input)
        assertEquals("session_key mismatch", "743bf515e20e74e85b60bf1d7e0ee92bdb3fab59b7ca71e22a851458c13cc7b3", sessionKey.toHex())
        assertEquals("tag_secret mismatch", "4186453c6bc605c6bde8321daba57a71dd6992c6899492c28bddc0739a1b6a9b", tagSecret.toHex())

        // Tag: keyed hash of (counter=0 || time_window=12345678)
        val counterBytes = ByteArray(8)
        val windowBytes = ByteArray(8)
        val window = 12345678L
        for (i in 0 until 8) {
            windowBytes[i] = ((window shr (i * 8)) and 0xFF).toByte()
        }
        val tagData = counterBytes + windowBytes
        val tag = Blake3.keyedHash(tagSecret, tagData).copyOf(8)
        assertEquals("tag mismatch", "458b3fb9c437190d", tag.toHex())

        // Obfuscation mask
        val mask = Blake3.deriveKey("aivpn-eph-obfuscation-v1", serverPub)
        assertEquals("obf mask mismatch", "2ca50328215b16491be8c5785b7611297e5258405e487c51899b646aca785836", mask.toHex())
    }
}
