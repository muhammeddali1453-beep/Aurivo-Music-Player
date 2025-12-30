from PyQt5.QtCore import QObject, pyqtSlot, pyqtSignal


def build_web_audio_capture_js():
    return r"""
(function() {
    if (window.__angollaCaptureInstalled) return;
    window.__angollaCaptureInstalled = true;
    window.__angollaLastPlaying = null;
    window.__angollaPendingPlay = false;
    window.__angollaBridgeReady = false;
    window.__angollaQueuedPlaying = null;
    window.__angollaListenersInstalled = false;
    window.__angollaPlayKickTimer = null;
    window.__angollaUserGestureTS = 0;
    window.__angollaAllowPlayUntil = 0;
    window.__angollaMuteWebAudio = false;
    window.__angollaPcmEnabled = true;
    window.__angollaHasGesture = false;
    window.__angollaAudioReady = false;

    function initBridge(callback) {
        try {
            if (window.AngollaBridge) {
                callback(window.AngollaBridge);
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
                    window.AngollaBridge = channel.objects.AngollaBridge;
                    window.bridge = window.AngollaBridge;
                    callback(window.AngollaBridge);
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
            if (window.__angollaAudioCtx && window.__angollaOutputGain) {
                // Use WebAudio gain; muting element can silence PCM capture.
                return;
            }
            var els = document.querySelectorAll('video, audio');
            for (var i = 0; i < els.length; i++) {
                var el = els[i];
                if (muted) {
                    if (typeof el.__angollaPrevVolume !== 'number') {
                        el.__angollaPrevVolume = el.volume;
                    }
                    el.muted = true;
                    el.volume = 0;
                } else {
                    el.muted = false;
                    if (typeof el.__angollaPrevVolume === 'number') {
                        el.volume = el.__angollaPrevVolume;
                    }
                }
            }
        } catch (e) {}
    }

    window.__angollaSetMuteWebAudio = function(muted) {
        window.__angollaMuteWebAudio = !!muted;
        applyMediaMute(window.__angollaMuteWebAudio);
        if (window.__angollaOutputGain) {
            try {
                window.__angollaOutputGain.gain.value = muted ? 0.0 : 1.0;
            } catch (e) {}
        }
    };

    window.__angollaSetPcmEnabled = function(enabled) {
        window.__angollaPcmEnabled = !!enabled;
    };

    window.__angollaSetWebVolume = function(vol) {
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
        window.__angollaUserGestureTS = now;
        window.__angollaHasGesture = true;
        initAudioFromGesture();
        if (evt && isExplicitPlayTarget(evt.target)) {
            window.__angollaAllowPlayUntil = now + 6000;
        }
    }

    function tryResumeAudioContext() {
        if (!window.__angollaAudioCtx) return;
        try {
            if (window.__angollaAudioCtx.state === 'suspended') {
                window.__angollaAudioCtx.resume();
            }
        } catch (e) {}
    }

    function userGestureAllowed() {
        return Date.now() <= window.__angollaAllowPlayUntil;
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
        if (!force && window.__angollaLastPlaying === playing) return;
        window.__angollaLastPlaying = playing;
        var bridge = window.AngollaBridge;
        if (!bridge) {
            window.__angollaQueuedPlaying = playing;
            return;
        }
        window.__angollaQueuedPlaying = null;
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
        if (!window.__angollaAudioCtx) return false;
        tryResumeAudioContext();

        if (!window.__angollaOutputGain) {
            window.__angollaOutputGain = window.__angollaAudioCtx.createGain();
            window.__angollaOutputGain.gain.value = window.__angollaMuteWebAudio ? 0.0 : 1.0;
        }

        if (!window.__angollaFreqData ||
            window.__angollaFreqData.length !== window.__angollaAnalyser.frequencyBinCount) {
            window.__angollaFreqData = new Uint8Array(
                window.__angollaAnalyser.frequencyBinCount
            );
        }
        if (!window.__angollaTimeData ||
            window.__angollaTimeData.length !== window.__angollaAnalyser.fftSize) {
            window.__angollaTimeData = new Uint8Array(
                window.__angollaAnalyser.fftSize
            );
        }
        return true;
    }

    function initAudioFromGesture() {
        if (!window.__angollaHasGesture) return false;
        if (!window.__angollaAudioCtx) {
            var AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (!AudioCtx) return false;
            try {
                window.__angollaAudioCtx = new AudioCtx({ sampleRate: 48000 });
            } catch (e) {
                window.__angollaAudioCtx = new AudioCtx();
            }
            window.__angollaAnalyser = window.__angollaAudioCtx.createAnalyser();
            window.__angollaAnalyser.fftSize = 2048;
            window.__angollaAnalyser.smoothingTimeConstant = 0.05; // 0.10 -> 0.05 (Saf ham ses, sıfıra yakın gecikme)
        }
        tryResumeAudioContext();
        window.__angollaAudioReady = window.__angollaAudioCtx &&
            window.__angollaAudioCtx.state === 'running';
        if (!window.__angollaOutputGain && window.__angollaAudioCtx) {
            window.__angollaOutputGain = window.__angollaAudioCtx.createGain();
            window.__angollaOutputGain.gain.value = window.__angollaMuteWebAudio ? 0.0 : 1.0;
        }
        ensureProcessor();
        return window.__angollaAudioReady;
    }

    window.__angollaInitAudioFromGesture = initAudioFromGesture;

    function ensureProcessor() {
        if (window.__angollaProcessor) return;
        if (!window.__angollaAudioCtx) return;
        var bufferSize = 1024;
        try {
            window.__angollaProcessor = window.__angollaAudioCtx.createScriptProcessor(
                bufferSize, 2, 2
            );
        } catch (e) {
            try {
                window.__angollaProcessor = window.__angollaAudioCtx.createScriptProcessor(
                    2048, 2, 2
                );
                bufferSize = 2048;
            } catch (err) {
                return;
            }
        }
        window.__angollaProcessor.onaudioprocess = function(evt) {
            try {
                if (!window.__angollaPcmEnabled) return;
                var bridge = window.AngollaBridge;
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
                bridge.send_web_audio_pcm(interleaved, input.sampleRate || window.__angollaAudioCtx.sampleRate, 2);
            } catch (e) {}
        };
    }

    function reportState(media) {
        var bridge = window.AngollaBridge;
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
        window.__angollaCurrentMedia = media;

        if (!media.__angollaEventsAttached) {
            media.__angollaEventsAttached = true;
            var onPlay = function() {
                if (!window.__angollaAudioCtx && window.__angollaHasGesture) {
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

        if (window.__angollaSource &&
            window.__angollaSource.__angollaMedia === media) {
            reportState(media);
            return;
        }

        try {
            if (window.__angollaSource) {
                window.__angollaSource.disconnect();
            }
            if (window.__angollaAnalyser) {
                window.__angollaAnalyser.disconnect();
            }
            if (window.__angollaProcessor) {
                window.__angollaProcessor.disconnect();
            }
            if (window.__angollaOutputGain) {
                window.__angollaOutputGain.disconnect();
            }
        } catch (e) {}

        try {
            var src = window.__angollaAudioCtx.createMediaElementAudioSource(media);
            src.__angollaMedia = media;
            src.connect(window.__angollaAnalyser);
            if (window.__angollaProcessor) {
                window.__angollaAnalyser.connect(window.__angollaProcessor);
                window.__angollaProcessor.connect(window.__angollaOutputGain);
                window.__angollaOutputGain.connect(window.__angollaAudioCtx.destination);
            } else {
                window.__angollaAnalyser.connect(window.__angollaOutputGain);
                window.__angollaOutputGain.connect(window.__angollaAudioCtx.destination);
            }
            window.__angollaSource = src;
        } catch (e) {}

        if (window.__angollaMuteWebAudio) {
            if (window.__angollaOutputGain) {
                window.__angollaOutputGain.gain.value = 0.0;
            }
        }

        reportState(media);
    }

    function sendFrame() {
        var bridge = window.AngollaBridge;
        var media = window.__angollaCurrentMedia;
        if (!bridge || typeof bridge.send_web_audio !== 'function' || !media) return;

        if (!ensureContext()) return;
        var analyser = window.__angollaAnalyser;
        var timeData = window.__angollaTimeData;
        var freqData = window.__angollaFreqData;

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
        if (!window.__angollaCaptureLoop) {
            window.__angollaCaptureLoop = setInterval(sendFrame, 16); // 20ms -> 16ms (60 FPS - Yerel mod ile aynı)
        }
        if (!window.__angollaStateLoop) {
            window.__angollaStateLoop = setInterval(function() {
                var media = pickActiveMedia();
                if (media) {
                    attachMedia(media);
                    reportState(media);
                }
            }, 500);
        }
    }

    function watchForVideo() {
        if (window.__angollaObserver) return;
        var root = document.documentElement || document.body;
        if (!root) return;
        window.__angollaObserver = new MutationObserver(function() {
            var list = getMediaElements();
            for (var i = 0; i < list.length; i++) {
                attachMedia(list[i]);
            }
            var media = pickActiveMedia();
            if (media) notifyPlaying(media);
        });
        window.__angollaObserver.observe(root, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src']
        });
    }

    function kickPlayDetection() {
        if (window.__angollaPlayKickTimer) return;
        var attempts = 0;
        window.__angollaPlayKickTimer = setInterval(function() {
            attempts += 1;
            var media = pickActiveMedia();
            if (media) {
                attachMedia(media);
                notifyPlaying(media, true);
                clearInterval(window.__angollaPlayKickTimer);
                window.__angollaPlayKickTimer = null;
                window.__angollaPendingPlay = false;
                setTimeout(function() { notifyPlaying(media); }, 1200);
                return;
            }
            if (attempts >= 12) {
                clearInterval(window.__angollaPlayKickTimer);
                window.__angollaPlayKickTimer = null;
                window.__angollaPendingPlay = false;
                sendPlaying(false, true);
            }
        }, 150);
    }

    function installListeners() {
        if (window.__angollaListenersInstalled) return;
        window.__angollaListenersInstalled = true;
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
                window.__angollaPendingPlay = true;
                initAudioFromGesture();
                if (window.__angollaCurrentMedia) {
                    attachMedia(window.__angollaCurrentMedia);
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
        window.__angollaBridgeReady = true;
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
        if (window.__angollaQueuedPlaying !== null) {
            sendPlaying(window.__angollaQueuedPlaying, true);
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
            console.log("✓ Angolla: YouTube JS Codec forcing active.");
        }
    } catch(e) {}

})();
"""


def build_web_playback_state_js():
    return r"""
(function() {
    if (window.__angollaPlaybackInstalled) return;
    window.__angollaPlaybackInstalled = true;

    function initBridge(callback) {
        try {
            if (window.AngollaBridge) {
                callback(window.AngollaBridge);
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
                    window.AngollaBridge = channel.objects.AngollaBridge;
                    window.bridge = window.AngollaBridge;
                    callback(window.AngollaBridge);
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
        var bridge = window.AngollaBridge;
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
        if (window.__angollaAdSkipInstalled) return;
        window.__angollaAdSkipInstalled = true;
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


class AngollaBridge(QObject):
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
    """QWebChannel köprüsünü kur ve AngollaBridge'i bağla."""
    from PyQt5.QtWebChannel import QWebChannel
    bridge = AngollaBridge()
    channel = QWebChannel()
    channel.registerObject('AngollaBridge', bridge)
    page.setWebChannel(channel)
    bridge.playbackStateChanged.connect(main_window._on_web_playback_state)
    if hasattr(main_window, "_on_web_video_playing"):
        bridge.videoPlaying.connect(main_window._on_web_video_playing)
    bridge.webAudioData.connect(main_window._process_web_audio)
    if hasattr(main_window, "_on_web_audio_pcm"):
        bridge.webAudioPcm.connect(main_window._on_web_audio_pcm)
    return bridge
