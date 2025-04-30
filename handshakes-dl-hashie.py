import logging
import json
import os
import glob
from datetime import datetime

import pwnagotchi
import pwnagotchi.plugins as plugins

from flask import abort
from flask import send_from_directory
from flask import render_template_string

TEMPLATE="""
{% extends "base.html" %}
{% set active_page = "handshakes" %}
{% block title %}
    {{ title }}
{% endblock %}
{% block styles %}
    {{ super() }}
    <style>
        #filter {
            width: 100%;
            font-size: 16px;
            padding: 12px 20px 12px 40px;
            border: 1px solid #ddd;
            margin-bottom: 12px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
    </style>
{% endblock %}
{% block script %}
    var filter = document.getElementById('filter');
    filter.onkeyup = function() {
        document.body.style.cursor = 'progress';
        var filterVal = filter.value.toUpperCase();
        var table, tr, td, i, txtValue;
        table = document.getElementById("fileTable");
        tr = table.getElementsByTagName("tr");
        for (i = 1; i < tr.length; i++) { // Skip the header row
            td = tr[i].getElementsByTagName("td")[1]; // Search in the filename column
            if (td) {
                txtValue = td.textContent || td.innerText;
                if (txtValue.toUpperCase().indexOf(filterVal) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
        }
        document.body.style.cursor = 'default';
    };

    // Convert UTC timestamps to local timezone
    document.querySelectorAll(".file-time").forEach(function(element) {
        var utcTime = element.getAttribute("data-utc");
        var localTime = new Date(utcTime).toLocaleString(); // Convert to local timezone
        element.textContent = localTime; // Replace content with local time
    });
{% endblock %}
{% block content %}
    <input type="text" id="filter" placeholder="Search for filenames..." title="Type in a filter">
    <table id="fileTable">
        <thead>
            <tr>
                <th>Updated Timestamp</th>
                <th>Filename</th>
            </tr>
        </thead>
        <tbody>
            {% for handshake in handshakes %}
                {% for ext in handshake.ext %}
                    <tr>
                        <td class="file-time" data-utc="{{ handshake.ts }}"></td>
                        <td>
                            <a href="/plugins/handshakes-dl-hashie/{{ handshake.name }}{{ ext }}">{{ handshake.name }}{{ ext }}</a>
                        </td>
                    </tr>
                {% endfor %}
            {% endfor %}
        </tbody>
    </table>
{% endblock %}
"""

class handshakes:
    def __init__(self, name, path, ext, ts):
        self.name = name
        self.path = path
        self.ext = ext
        self.ts = ts  # Timestamp of the file

class HandshakesDL(plugins.Plugin):
    __author__ = 'me@sayakb.com'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Download handshake captures from web-ui.'

    def __init__(self):
        self.ready = False

    def on_loaded(self):
        logging.info("[HandshakesDL] plugin loaded")

    def on_config_changed(self, config):
        self.config = config
        self.ready = True

    def on_webhook(self, path, request):
        if not self.ready:
            return "Plugin not ready"

        if path == "/" or not path:
            pcapfiles = glob.glob(os.path.join(self.config['bettercap']['handshakes'], "*.pcap"))

            data = []
            for path in pcapfiles:
                name = os.path.basename(path)[:-5]
                fullpathNoExt = path[:-5]
                possibleExt = ['.2500', '.16800', '.22000']
                foundExt = ['.pcap']
                for ext in possibleExt:
                    if os.path.isfile(fullpathNoExt + ext):
                        foundExt.append(ext)

                # Get the last modified time of the file
                ts = os.path.getmtime(path)
                ts_iso = datetime.utcfromtimestamp(ts).isoformat() + "Z"
                data.append(handshakes(name, fullpathNoExt, foundExt, ts_iso))

            # Sort the data by timestamp (latest first)
            data.sort(key=lambda x: x.ts, reverse=True)

            return render_template_string(
                TEMPLATE,
                title="Handshakes | " + pwnagotchi.name(),
                handshakes=data
            )
        else:
            dir = self.config['bettercap']['handshakes']
            try:
                logging.info(f"[HandshakesDL] serving {dir}/{path}")
                return send_from_directory(dir, path, as_attachment=True)
            except FileNotFoundError:
                abort(404)
