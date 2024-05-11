import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { AttachAddon } from '@xterm/addon-attach';

const xterm = new Terminal();
const fit = new FitAddon();
xterm.loadAddon(fit);

const searchParams = new URLSearchParams(window.location.search);
const sessionId = searchParams.get('id');
const ws = new WebSocket('ws://' + window.location.host + '/ws/' + sessionId);

function resize() {
    fit.fit();
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'resize',
            cols: xterm.cols,
            rows: xterm.rows
        }));
    }
}

ws.onopen = () => {
    console.log('WebSocket connected');
    xterm.loadAddon(new AttachAddon(ws));
    xterm.open(document.getElementById('terminal'));
    xterm.focus();
    resize();
};

ws.onclose = () => {
    console.log('WebSocket closed');
}

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
}

ws.onmessage = (event) => {
    console.log('WebSocket message:', event.data);
}

window.addEventListener('resize', resize);

