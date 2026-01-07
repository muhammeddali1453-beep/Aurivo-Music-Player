from PyQt5.QtCore import QObject, pyqtSlot, pyqtSignal


def build_web_audio_capture_js():
    return r"""
(function() {
    if (window.__aurivoCaptureInstalled) return;
    window.__aurivoCaptureInstalled = true;
    window.__aurivoLastPlaying = null;
    window.__aurivoPendingPlay = false;
    window.__aurivoBridgeReady = false;
    window.__aurivoQueuedPlaying = null;
    window.__aurivoListenersInstalled = false;
    window.__aurivoPlayKickTimer = null;
    window.__aurivoUserGestureTS = 0;
    window.__aurivoAllowPlayUntil = 0;
    window.__aurivoMuteWebAudio = false;
    window.__aurivoPcmEnabled = true;
    window.__aurivoHasGesture = false;
    window.__aurivoAudioReady = false;

    function initBridge(callback) {
        try {
            if (window.AurivoBridge) {
                callback(window.AurivoBridge);
                return;
            }
            if (!window.qt || !window.qt.webChannelTransport) {
                setTimeout(function() { initBridge(callback); }, 400);
                return;
            }
            function attachChannel() {
                if (typeof QWebChannel === 'undefined') {
                    setTimeout(attachChannel, 200);
                    return;
                }
                new QWebChannel(qt.webChannelTransport, function(channel) {
                    window.AurivoBridge = channel.objects.AurivoBridge;
                    window.bridge = window.AurivoBridge;
                    callback(window.AurivoBridge);
                });
            }
            if (typeof QWebChannel === 'undefined') {
                var s = document.createElement('script');
                s.src = 'qrc:///qtwebchannel/qwebchannel.js';
                s.onload = attachChannel;
                document.head.appendChild(s);
            } else {
                attachChannel();
            }
        } catch (e) {}
    }

    function getMediaElement() {
        return document.querySelector('video, audio');
    }

    function getMediaElements() {
        return Array.from(document.querySelectorAll('video, audio'));
    }

    function isAdActive() {
        try {
            var adNode = document.querySelector(
                '.ad-showing, .ytp-ad-player-overlay, .ytp-ad-module,' +
                ' .ad-interrupting, [data-ad], [data-ad-slot]'
            );
            if (!adNode) return false;
            return adNode.offsetParent !== null;
        } catch (e) {
            return false;
        }
    }

    function isPlaying(media) {
        return !!media && !media.paused && !media.ended && (media.readyState || 0) > 2;
    }

    function applyMediaMute(muted) {
        try {
            if (window.__aurivoAudioCtx && window.__aurivoOutputGain) {
                // Use WebAudio gain; muting element can silence PCM capture.
                return;
            }
            var els = document.querySelectorAll('video, audio');
            for (var i = 0; i < els.length; i++) {
                var el = els[i];
                if (muted) {
                    if (typeof el.__aurivoPrevVolume !== 'number') {
                        el.__aurivoPrevVolume = el.volume;
                    }
                    el.muted = true;
                    el.volume = 0;
                } else {
                    el.muted = false;
                    if (typeof el.__aurivoPrevVolume === 'number') {
                        el.volume = el.__aurivoPrevVolume;
                    }
                }
            }
        } catch (e) {}
    }

    window.__aurivoSetMuteWebAudio = function(muted) {
        window.__aurivoMuteWebAudio = !!muted;
        applyMediaMute(window.__aurivoMuteWebAudio);
        if (window.__aurivoOutputGain) {
            try {
                window.__aurivoOutputGain.gain.value = muted ? 0.0 : 1.0;
            } catch (e) {}
        }
    };

    window.__aurivoSetPcmEnabled = function(enabled) {
        window.__aurivoPcmEnabled = !!enabled;
    };

    window.__aurivoSetWebVolume = function(vol) {
        var v = Math.max(0.0, Math.min(1.0, Number(vol) || 0));
        try {
            var els = document.querySelectorAll('video, audio');
            for (var i = 0; i < els.length; i++) {
                var el = els[i];
                el.volume = v;
                el.muted = false;
            }
        } catch (e) {}
    };

    function markUserGesture(evt) {
        if (evt && evt.isTrusted === false) return;
        var now = Date.now();
        window.__aurivoUserGestureTS = now;
        window.__aurivoHasGesture = true;
        initAudioFromGesture();
        if (evt && isExplicitPlayTarget(evt.target)) {
            window.__aurivoAllowPlayUntil = now + 6000;
        }
    }

    function tryResumeAudioContext() {
        if (!window.__aurivoAudioCtx) return;
        try {
            if (window.__aurivoAudioCtx.state === 'suspended') {
                window.__aurivoAudioCtx.resume();
            }
        } catch (e) {}
    }

    function userGestureAllowed() {
        return Date.now() <= window.__aurivoAllowPlayUntil;
    }

    function isExplicitPlayTarget(target) {
        if (!target || !target.closest) return false;
        return !!target.closest(
            'video, audio, .ytp-play-button, button[aria-label*="Play"],' +
            ' button[title*="Play"], a#thumbnail, ytd-thumbnail'
        );
    }

    function shouldBlockAutoplay(media) {
        if (!media) return false;

        // YouTube Hover/Preview Engelleme (Öncelikli)
        try {
            if (window.location.hostname.indexOf('youtube.com') !== -1) {
                if (media.closest && (
                    media.closest('ytd-thumbnail') || 
                    media.closest('#inline-player') || 
                    media.closest('ytd-inline-preview-player') ||
                    media.closest('.ytd-video-preview') ||
                    media.closest('ytd-rich-grid-media')
                )) {
                    var isMain = media.closest('#movie_player') && !media.closest('ytd-inline-preview-player');
                    if (!isMain) return true;
                }
            }
        } catch(e) {}

        if (userGestureAllowed()) return false;

        var muted = media.muted || media.volume === 0;
        var autoplayAttr = !!media.autoplay || media.hasAttribute('autoplay');
        if (muted && (autoplayAttr || media.loop || media.playsInline)) {
            return true;
        }
        return false;
    }

    function blockAutoplay(media) {
        try {
            media.pause();
            media.currentTime = 0;
            if (media.autoplay) media.autoplay = false;
            if (media.removeAttribute) media.removeAttribute('autoplay');
        } catch (e) {}
        sendPlaying(false, true);
    }

    function sendPlaying(playing, force) {
        if (!force && window.__aurivoLastPlaying === playing) return;
        window.__aurivoLastPlaying = playing;
        var bridge = window.AurivoBridge;
        if (!bridge) {
            window.__aurivoQueuedPlaying = playing;
            return;
        }
        window.__aurivoQueuedPlaying = null;
        if (typeof bridge.report_video_playing === 'function') {
            bridge.report_video_playing(playing);
        }
        if (typeof bridge.on_youtube_play === 'function') {
            bridge.on_youtube_play(playing);
        }
    }

    function notifyPlaying(media, forcePlaying) {
        var playing = forcePlaying ? true : isPlaying(media);
        if (playing && isAdActive()) {
            playing = false;
        }
        sendPlaying(playing, false);
    }

    function pickActiveMedia() {
        var list = getMediaElements();
        if (!list.length) return null;
        for (var i = 0; i < list.length; i++) {
            if (isPlaying(list[i])) return list[i];
        }
        for (var j = 0; j < list.length; j++) {
            if ((list[j].readyState || 0) > 0) return list[j];
        }
        return list[0];
    }

    function ensureContext() {
        if (!window.__aurivoAudioCtx) return false;
        tryResumeAudioContext();

        if (!window.__aurivoOutputGain) {
            window.__aurivoOutputGain = window.__aurivoAudioCtx.createGain();
            window.__aurivoOutputGain.gain.value = window.__aurivoMuteWebAudio ? 0.0 : 1.0;
        }

        if (!window.__aurivoFreqData ||
            window.__aurivoFreqData.length !== window.__aurivoAnalyser.frequencyBinCount) {
            window.__aurivoFreqData = new Uint8Array(
                window.__aurivoAnalyser.frequencyBinCount
            );
        }
        if (!window.__aurivoTimeData ||
            window.__aurivoTimeData.length !== window.__aurivoAnalyser.fftSize) {
            window.__aurivoTimeData = new Uint8Array(
                window.__aurivoAnalyser.fftSize
            );
        }
        return true;
    }

    function initAudioFromGesture() {
        if (!window.__aurivoHasGesture) return false;
        if (!window.__aurivoAudioCtx) {
            var AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (!AudioCtx) return false;
            try {
                window.__aurivoAudioCtx = new AudioCtx({ sampleRate: 48000 });
            } catch (e) {
                window.__aurivoAudioCtx = new AudioCtx();
            }
            window.__aurivoAnalyser = window.__aurivoAudioCtx.createAnalyser();
            window.__aurivoAnalyser.fftSize = 2048;
            window.__aurivoAnalyser.smoothingTimeConstant = 0.05; // 0.10 -> 0.05 (Saf ham ses, sıfıra yakın gecikme)
        }
        tryResumeAudioContext();
        window.__aurivoAudioReady = window.__aurivoAudioCtx &&
            window.__aurivoAudioCtx.state === 'running';
        if (!window.__aurivoOutputGain && window.__aurivoAudioCtx) {
            window.__aurivoOutputGain = window.__aurivoAudioCtx.createGain();
            window.__aurivoOutputGain.gain.value = window.__aurivoMuteWebAudio ? 0.0 : 1.0;
        }
        ensureProcessor();
        return window.__aurivoAudioReady;
    }

    window.__aurivoInitAudioFromGesture = initAudioFromGesture;

    function ensureProcessor() {
        if (window.__aurivoProcessor) return;
        if (!window.__aurivoAudioCtx) return;
        var bufferSize = 1024;
        try {
            window.__aurivoProcessor = window.__aurivoAudioCtx.createScriptProcessor(
                bufferSize, 2, 2
            );
        } catch (e) {
            try {
                window.__aurivoProcessor = window.__aurivoAudioCtx.createScriptProcessor(
                    2048, 2, 2
                );
                bufferSize = 2048;
            } catch (err) {
                return;
            }
        }
        window.__aurivoProcessor.onaudioprocess = function(evt) {
            try {
                if (!window.__aurivoPcmEnabled) return;
                var bridge = window.AurivoBridge;
                if (!bridge || typeof bridge.send_web_audio_pcm !== 'function') return;
                var input = evt.inputBuffer;
                if (!input || input.length === 0) return;
                var ch0 = input.getChannelData(0);
                var ch1 = input.numberOfChannels > 1 ? input.getChannelData(1) : ch0;
                var frames = input.length;
                var interleaved = new Array(frames * 2);
                for (var i = 0; i < frames; i++) {
                    interleaved[i * 2] = ch0[i];
                    interleaved[i * 2 + 1] = ch1[i];
                }
                bridge.send_web_audio_pcm(interleaved, input.sampleRate || window.__aurivoAudioCtx.sampleRate, 2);
            } catch (e) {}
        };
    }

    function reportState(media) {
        var bridge = window.AurivoBridge;
        if (!bridge || typeof bridge.report_playback_state !== 'function') return;
        var paused = !!media.paused;
        var ended = !!media.ended;
        var loading = (media.readyState || 0) < 2;
        var adActive = isAdActive();
        var videoCount = document.getElementsByTagName('video').length;
        bridge.report_playback_state(paused, ended, loading, adActive, videoCount);
        notifyPlaying(media);
    }

    function attachMedia(media) {
        if (!media) return;
        window.__aurivoCurrentMedia = media;

        if (!media.__aurivoEventsAttached) {
            media.__aurivoEventsAttached = true;
            var onPlay = function() {
                if (!window.__aurivoAudioCtx && window.__aurivoHasGesture) {
                    initAudioFromGesture();
                } else {
                    tryResumeAudioContext();
                }
                ensureContext();
                if (shouldBlockAutoplay(media)) {
                    blockAutoplay(media);
                    return;
                }
                reportState(media);
            };
            var onPause = function() { reportState(media); };

            media.addEventListener('play', onPlay);
            media.addEventListener('playing', onPlay);
            media.addEventListener('pause', onPause);
            media.addEventListener('ended', onPause);
            media.addEventListener('waiting', onPause);
            media.addEventListener('seeking', onPause);
            media.addEventListener('loadeddata', onPause);
            media.addEventListener('canplay', onPause);
            media.addEventListener('canplaythrough', onPause);
        }

        if (!ensureContext()) {
            return;
        }
        ensureProcessor();

        if (window.__aurivoSource &&
            window.__aurivoSource.__aurivoMedia === media) {
            reportState(media);
            return;
        }

        try {
            if (window.__aurivoSource) {
                window.__aurivoSource.disconnect();
            }
            if (window.__aurivoAnalyser) {
                window.__aurivoAnalyser.disconnect();
            }
            if (window.__aurivoProcessor) {
                window.__aurivoProcessor.disconnect();
            }
            if (window.__aurivoOutputGain) {
                window.__aurivoOutputGain.disconnect();
            }
        } catch (e) {}

        try {
            var src = window.__aurivoAudioCtx.createMediaElementAudioSource(media);
            src.__aurivoMedia = media;
            src.connect(window.__aurivoAnalyser);
            if (window.__aurivoProcessor) {
                window.__aurivoAnalyser.connect(window.__aurivoProcessor);
                window.__aurivoProcessor.connect(window.__aurivoOutputGain);
                window.__aurivoOutputGain.connect(window.__aurivoAudioCtx.destination);
            } else {
                window.__aurivoAnalyser.connect(window.__aurivoOutputGain);
                window.__aurivoOutputGain.connect(window.__aurivoAudioCtx.destination);
            }
            window.__aurivoSource = src;
        } catch (e) {}

        if (window.__aurivoMuteWebAudio) {
            if (window.__aurivoOutputGain) {
                window.__aurivoOutputGain.gain.value = 0.0;
            }
        }

        reportState(media);
    }

    function sendFrame() {
        var bridge = window.AurivoBridge;
        var media = window.__aurivoCurrentMedia;
        if (!bridge || typeof bridge.send_web_audio !== 'function' || !media) return;

        if (!ensureContext()) return;
        var analyser = window.__aurivoAnalyser;
        var timeData = window.__aurivoTimeData;
        var freqData = window.__aurivoFreqData;

        var adActive = isAdActive();
        var paused = !!media.paused;
        var ended = !!media.ended;
        var loading = (media.readyState || 0) < 2;
        notifyPlaying(media);

        analyser.getByteTimeDomainData(timeData);
        var sum = 0.0;
        for (var i = 0; i < timeData.length; i++) {
            var v = (timeData[i] - 128) / 128;
            sum += v * v;
        }
        var rms = Math.sqrt(sum / timeData.length);
        var rmsDb = 20 * Math.log10(rms + 1e-12);

        if (adActive || paused || ended || loading || rmsDb < -60) {
            bridge.send_web_audio(new Array(96).fill(0));
            return;
        }

        analyser.getByteFrequencyData(freqData);
        bridge.send_web_audio(Array.from(freqData.slice(0, 96)));
    }

    function startLoops() {
        if (!window.__aurivoCaptureLoop) {
            window.__aurivoCaptureLoop = setInterval(sendFrame, 16); // 20ms -> 16ms (60 FPS - Yerel mod ile aynı)
        }
        if (!window.__aurivoStateLoop) {
            window.__aurivoStateLoop = setInterval(function() {
                var media = pickActiveMedia();
                if (media) {
                    attachMedia(media);
                    reportState(media);
                }
            }, 500);
        }
    }

    function watchForVideo() {
        if (window.__aurivoObserver) return;
        var root = document.documentElement || document.body;
        if (!root) return;
        window.__aurivoObserver = new MutationObserver(function() {
            var list = getMediaElements();
            for (var i = 0; i < list.length; i++) {
                attachMedia(list[i]);
            }
            var media = pickActiveMedia();
            if (media) notifyPlaying(media);
        });
        window.__aurivoObserver.observe(root, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src']
        });
    }

    function kickPlayDetection() {
        if (window.__aurivoPlayKickTimer) return;
        var attempts = 0;
        window.__aurivoPlayKickTimer = setInterval(function() {
            attempts += 1;
            var media = pickActiveMedia();
            if (media) {
                attachMedia(media);
                notifyPlaying(media, true);
                clearInterval(window.__aurivoPlayKickTimer);
                window.__aurivoPlayKickTimer = null;
                window.__aurivoPendingPlay = false;
                setTimeout(function() { notifyPlaying(media); }, 1200);
                return;
            }
            if (attempts >= 12) {
                clearInterval(window.__aurivoPlayKickTimer);
                window.__aurivoPlayKickTimer = null;
                window.__aurivoPendingPlay = false;
                sendPlaying(false, true);
            }
        }, 150);
    }

    function installListeners() {
        if (window.__aurivoListenersInstalled) return;
        window.__aurivoListenersInstalled = true;
        document.addEventListener('play', function(evt) {
            var target = evt.target;
            if (target && (target.tagName === 'VIDEO' || target.tagName === 'AUDIO')) {
                attachMedia(target);
                notifyPlaying(target);
            }
        }, true);
        document.addEventListener('pause', function(evt) {
            var target = evt.target;
            if (target && (target.tagName === 'VIDEO' || target.tagName === 'AUDIO')) {
                notifyPlaying(target);
            }
        }, true);
        document.addEventListener('click', function(evt) {
            markUserGesture(evt);
            if (evt && evt.isTrusted === false) {
                return;
            }
            if (isExplicitPlayTarget(evt.target)) {
                window.__aurivoPendingPlay = true;
                initAudioFromGesture();
                if (window.__aurivoCurrentMedia) {
                    attachMedia(window.__aurivoCurrentMedia);
                }
                sendPlaying(true, true);
                kickPlayDetection();
            }
        }, true);
        document.addEventListener('pointerdown', markUserGesture, true);
        document.addEventListener('keydown', markUserGesture, true);
        document.addEventListener('touchstart', markUserGesture, true);
    }

    installListeners();
    watchForVideo();

    initBridge(function() {
        window.__aurivoBridgeReady = true;
        ensureContext();
        var media = pickActiveMedia();
        if (media) {
            attachMedia(media);
            notifyPlaying(media, true);
        }
        var allMedia = getMediaElements();
        for (var i = 0; i < allMedia.length; i++) {
            attachMedia(allMedia[i]);
        }
        if (window.__aurivoQueuedPlaying !== null) {
            sendPlaying(window.__aurivoQueuedPlaying, true);
        }
        watchForVideo();
        startLoops();
    });
    // YouTube Codec Zorlaması (Software Rendering)
    try {
        if (window.location.hostname.indexOf('youtube.com') !== -1) {
            var originalCanPlayType = document.createElement('video').canPlayType;
            document.createElement('video').canPlayType = function(type) {
                if (type && (type.indexOf('codecs="vp9"') !== -1 || type.indexOf('codecs="av01"') !== -1)) {
                    return '';
                }
                return 'maybe';
            };
            console.log("✓ Aurivo: YouTube JS Codec forcing active.");
        }
    } catch(e) {}

})();
"""


def build_web_playback_state_js():
    return r"""
(function() {
    if (window.__aurivoPlaybackInstalled) return;
    window.__aurivoPlaybackInstalled = true;

    function initBridge(callback) {
        try {
            if (window.AurivoBridge) {
                callback(window.AurivoBridge);
                return;
            }
            if (!window.qt || !window.qt.webChannelTransport) {
                setTimeout(function() { initBridge(callback); }, 400);
                return;
            }
            function attachChannel() {
                if (typeof QWebChannel === 'undefined') {
                    setTimeout(attachChannel, 200);
                    return;
                }
                new QWebChannel(qt.webChannelTransport, function(channel) {
                    window.AurivoBridge = channel.objects.AurivoBridge;
                    window.bridge = window.AurivoBridge;
                    callback(window.AurivoBridge);
                });
            }
            if (typeof QWebChannel === 'undefined') {
                var s = document.createElement('script');
                s.src = 'qrc:///qtwebchannel/qwebchannel.js';
                s.onload = attachChannel;
                document.head.appendChild(s);
            } else {
                attachChannel();
            }
        } catch (e) {}
    }

    function isAdActive() {
        try {
            var adNode = document.querySelector(
                '.ad-showing, .ytp-ad-player-overlay, .ytp-ad-module,' +
                ' .ad-interrupting, [data-ad], [data-ad-slot]'
            );
            if (!adNode) return false;
            return adNode.offsetParent !== null;
        } catch (e) {
            return false;
        }
    }

    function reportState() {
        var bridge = window.AurivoBridge;
        if (!bridge || typeof bridge.report_playback_state !== 'function') return;
        var media = document.querySelector('video, audio');
        var paused = true;
        var ended = false;
        var loading = true;
        if (media) {
            paused = !!media.paused;
            ended = !!media.ended;
            loading = (media.readyState || 0) < 2;
        }
        var adActive = isAdActive();
        var videoCount = document.getElementsByTagName('video').length;
        bridge.report_playback_state(paused, ended, loading, adActive, videoCount);
    }

    initBridge(function() {
        reportState();
        setInterval(reportState, 500);
    });
})();
"""

def build_ad_skip_js(interval_ms=250):
    return f"""
(function(){{
    try {{
        if (window.__aurivoAdSkipInstalled) return;
        window.__aurivoAdSkipInstalled = true;
        setInterval(function(){{
            try {{
                var btn = document.querySelector(
                    '.ytp-ad-skip-button-modern, .ytp-ad-skip-button, .ytp-skip-ad-button'
                );
                if (btn && btn.offsetParent !== null) {{
                    btn.click();
                }}
            }} catch(e) {{}}
        }}, {int(interval_ms)});
    }} catch(e) {{}}
}})();
"""


class AurivoBridge(QObject):
    playbackStateChanged = pyqtSignal(bool, bool, bool, bool, int)  # paused, ended, loading, adActive, videoCount
    videoPlaying = pyqtSignal(bool)
    webAudioData = pyqtSignal(list)
    webAudioPcm = pyqtSignal(list, int, int)

    @pyqtSlot(bool, bool, bool, bool, int)
    def report_playback_state(self, paused, ended, loading, adActive, videoCount=0):
        self.playbackStateChanged.emit(paused, ended, loading, adActive, int(videoCount))

    @pyqtSlot(list)
    def send_web_audio(self, band_vals):
        self.webAudioData.emit(band_vals)

    @pyqtSlot(list, int, int)
    def send_web_audio_pcm(self, samples, sample_rate, channels):
        self.webAudioPcm.emit(samples, int(sample_rate), int(channels))

    @pyqtSlot(bool)
    def report_video_playing(self, playing):
        self.videoPlaying.emit(bool(playing))

    @pyqtSlot(bool)
    def on_youtube_play(self, playing):
        self.videoPlaying.emit(bool(playing))


def setup_web_channel(page, main_window):
    """QWebChannel köprüsünü kur ve AurivoBridge'i bağla."""
    from PyQt5.QtWebChannel import QWebChannel
    bridge = AurivoBridge()
    channel = QWebChannel()
    channel.registerObject('AurivoBridge', bridge)
    page.setWebChannel(channel)
    bridge.playbackStateChanged.connect(main_window._on_web_playback_state)
    if hasattr(main_window, "_on_web_video_playing"):
        bridge.videoPlaying.connect(main_window._on_web_video_playing)
    bridge.webAudioData.connect(main_window._process_web_audio)
    if hasattr(main_window, "_on_web_audio_pcm"):
        bridge.webAudioPcm.connect(main_window._on_web_audio_pcm)
    return bridge
