package com.aivpn.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.aivpn.client.databinding.ActivityMainBinding

/**
 * Main screen — server address, public key, connect/disconnect button,
 * connection timer, traffic stats, and EN/RU language toggle.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var isConnected = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, getString(R.string.error_vpn_denied), Toast.LENGTH_SHORT).show()
        }
    }

    // Connection timer
    private val timerHandler = Handler(Looper.getMainLooper())
    private var connectionStartTime = 0L
    private val timerRunnable = object : Runnable {
        override fun run() {
            if (isConnected && connectionStartTime > 0) {
                val elapsed = (System.currentTimeMillis() - connectionStartTime) / 1000
                val h = elapsed / 3600
                val m = (elapsed % 3600) / 60
                val s = elapsed % 60
                binding.textTimer.text = String.format("%02d:%02d:%02d", h, m, s)
                binding.textDuration.text = String.format("%02d:%02d", h * 60 + m, s)
                timerHandler.postDelayed(this, 1000)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Restore saved credentials
        val prefs = getSharedPreferences("aivpn", MODE_PRIVATE)
        binding.editServer.setText(prefs.getString("server", ""))
        binding.editServerKey.setText(prefs.getString("server_key", ""))

        // Update language button label
        updateLanguageButton()

        binding.btnConnect.setOnClickListener {
            if (isConnected) {
                disconnect()
            } else {
                connect()
            }
        }

        binding.btnLanguage.setOnClickListener {
            toggleLanguage()
        }

        // Listen for service status updates
        AivpnService.statusCallback = { connected, statusText ->
            runOnUiThread {
                isConnected = connected
                updateUI(connected, statusText)
            }
        }

        // Listen for traffic stats updates
        AivpnService.trafficCallback = { uploadBytes, downloadBytes ->
            runOnUiThread {
                binding.textUpload.text = formatBytes(uploadBytes)
                binding.textDownload.text = formatBytes(downloadBytes)
            }
        }
    }

    private fun connect() {
        val server = binding.editServer.text.toString().trim()
        val serverKey = binding.editServerKey.text.toString().trim()

        if (server.isEmpty() || serverKey.isEmpty()) {
            Toast.makeText(this, getString(R.string.error_fill_fields), Toast.LENGTH_SHORT).show()
            return
        }

        // Save credentials
        getSharedPreferences("aivpn", MODE_PRIVATE).edit()
            .putString("server", server)
            .putString("server_key", serverKey)
            .apply()

        // Request VPN permission from the system
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun disconnect() {
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun startVpnService() {
        val server = binding.editServer.text.toString().trim()
        val serverKey = binding.editServerKey.text.toString().trim()

        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("server", server)
            putExtra("server_key", serverKey)
        }
        startForegroundService(intent)
        updateUI(true, getString(R.string.status_connecting))
    }

    private fun updateUI(connected: Boolean, statusText: String) {
        isConnected = connected
        binding.btnConnect.text = getString(
            if (connected) R.string.btn_disconnect else R.string.btn_connect
        )
        binding.btnConnect.setBackgroundColor(
            getColor(if (connected) R.color.disconnect else R.color.accent)
        )
        binding.textStatus.text = statusText
        binding.statusDot.setBackgroundResource(
            if (connected) R.drawable.dot_green else R.drawable.dot_grey
        )

        // Show/hide stats and timer
        val statsVisibility = if (connected) View.VISIBLE else View.GONE
        binding.textTimer.visibility = statsVisibility
        binding.statsRow.visibility = statsVisibility

        // Lock/unlock input fields while connected
        binding.editServer.isEnabled = !connected
        binding.editServerKey.isEnabled = !connected

        // Timer management
        if (connected && connectionStartTime == 0L) {
            connectionStartTime = System.currentTimeMillis()
            timerHandler.post(timerRunnable)
        } else if (!connected) {
            connectionStartTime = 0L
            timerHandler.removeCallbacks(timerRunnable)
            binding.textTimer.text = "00:00:00"
            binding.textUpload.text = "0 B"
            binding.textDownload.text = "0 B"
            binding.textDuration.text = "00:00"
        }
    }

    private fun toggleLanguage() {
        val prefs = getSharedPreferences("aivpn", MODE_PRIVATE)
        val currentLang = prefs.getString("language", "en") ?: "en"
        val newLang = if (currentLang == "en") "ru" else "en"

        prefs.edit().putString("language", newLang).apply()

        val localeList = LocaleListCompat.forLanguageTags(newLang)
        AppCompatDelegate.setApplicationLocales(localeList)
    }

    private fun updateLanguageButton() {
        val prefs = getSharedPreferences("aivpn", MODE_PRIVATE)
        val lang = prefs.getString("language", null)

        // Apply saved language on startup
        if (lang != null) {
            val localeList = LocaleListCompat.forLanguageTags(lang)
            AppCompatDelegate.setApplicationLocales(localeList)
        }

        val currentLang = (prefs.getString("language", "en") ?: "en").uppercase()
        binding.btnLanguage.text = if (currentLang == "EN") "EN → RU" else "RU → EN"
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
            else -> String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    override fun onDestroy() {
        AivpnService.statusCallback = null
        AivpnService.trafficCallback = null
        timerHandler.removeCallbacks(timerRunnable)
        super.onDestroy()
    }
}
