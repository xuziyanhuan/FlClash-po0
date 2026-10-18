package com.follow.clash.plugins

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import com.follow.clash.common.Components
import com.follow.clash.common.registerReceiverCompat
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class Po0ScreenPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {

    private lateinit var channel: MethodChannel

    private var context: Context? = null

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val screenOn = when (intent?.action) {
                Intent.ACTION_SCREEN_ON -> true
                Intent.ACTION_SCREEN_OFF -> false
                else -> return
            }
            channel.invokeMethod("screenChanged", screenOn)
        }
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "${Components.PACKAGE_NAME}/po0_screen")
        channel.setMethodCallHandler(this)
        val appContext = binding.applicationContext
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        appContext.registerReceiverCompat(receiver, filter)
        context = appContext
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context?.unregisterReceiver(receiver)
        context = null
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isScreenOn" -> result.success(
                (context?.getSystemService(Context.POWER_SERVICE) as? PowerManager)
                    ?.isInteractive ?: true,
            )

            else -> result.notImplemented()
        }
    }
}
