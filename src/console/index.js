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
        const size = { cols: xterm.cols, rows: xterm.rows };
        const blob = new Blob([JSON.stringify(size)], { type: "application/json" });
        ws.send(blob);
    }
}

ws.onopen = () => {
    console.log('WebSocket connected');
    xterm.loadAddon(new AttachAddon(ws));
    xterm.open(document.getElementById('terminal'));
    fit.activate(xterm);
    xterm.focus();
    resize();
};

ws.onclose = () => {
    console.log('WebSocket closed');
    xterm.writeln('Connection closed');
}

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
}

window.addEventListener('resize', resize);