const $ = id => document.getElementById(id);


/* =========================================================
   API
   ========================================================= */

async function api(url, opt) {

    const r = await fetch(url, opt);

    if (!r.ok) {
        throw Error(await r.text());
    }

    return r.json();
}


/* =========================================================
   TOAST
   ========================================================= */

function toast(message) {

    $("toast").textContent = message;

    $("toast").style.display = "block";

    setTimeout(() => {

        $("toast").style.display = "none";

    }, 2500);
}


/* =========================================================
   TAB SWITCHING
   ========================================================= */

function showTab(id, btn) {

    document
        .querySelectorAll(".tab")
        .forEach(x => {

            x.classList.add("hidden");

        });


    const target = $(id);

    if (target) {
        target.classList.remove("hidden");
    }


    document
        .querySelectorAll(".nav")
        .forEach(x => {

            x.classList.remove("active");

        });


    if (btn) {
        btn.classList.add("active");
    }


    const titles = {

        overview: "SOC Overview",

        alerts: "Security Alerts",

        traffic: "Analysed Traffic",

        ledger: "Secure Event Ledger"

    };


    if ($("title")) {

        $("title").textContent =
            titles[id] || "CipherGrid SOC";

    }


    if (id === "alerts") {
        loadAlerts();
    }


    if (id === "traffic") {
        loadFlows();
    }


    if (id === "ledger") {
        loadLedger();
    }

}


/* =========================================================
   ALERT / EVENT TABLE
   ========================================================= */

function table(rows) {

    if (!rows || !rows.length) {

        return `
            <div class="empty">
                No events yet.
            </div>
        `;

    }


    return `

        <div class="row head">

            <span>
                Time
            </span>

            <span>
                Threat
            </span>

            <span>
                Severity
            </span>

            <span>
                Confidence
            </span>

            <span>
                Flow
            </span>

            <span>
                Recommendation
            </span>

        </div>


        ${rows.map(x => `

            <div class="row">


                <span>

                    ${
                        x.timestamp
                        ? new Date(
                            x.timestamp
                          ).toLocaleString()
                        : "N/A"
                    }

                </span>


                <span>

                    <b>
                        ${x.threat || "Unknown"}
                    </b>

                </span>


                <span>

                    <i class="sev ${x.severity || "Low"}">

                        ${x.severity || "Low"}

                    </i>

                </span>


                <span>

                    ${x.confidence ?? 0}%

                </span>


                <span
                    class="link"
                    onclick='detail(${JSON.stringify(x).replace(/'/g, "&#39;")})'>

                    ${x.flow_id || "N/A"}

                </span>


                <span>

                    <div class="recommend">

                        ${
                            x.recommendation ||
                            "No recommendation available."
                        }

                    </div>

                </span>


            </div>

        `).join("")}

    `;

}


/* =========================================================
   ALERT DETAIL
   FLOW ID → ALERT TAB → DETAIL AT TOP
   ========================================================= */

function detail(x) {


    /*
       Find the Alerts navigation button.
    */

    const navButtons =
        document.querySelectorAll(".nav");


    const alertsButton =
        navButtons.length > 1
            ? navButtons[1]
            : null;


    /*
       Open Alerts tab.
    */

    showTab(
        "alerts",
        alertsButton
    );


    /*
       Find detail panel.
    */

    const detailPanel =
        $("detail");


    if (!detailPanel) {
        return;
    }


    /*
       Show detail panel.
    */

    detailPanel.classList.remove("hidden");


    /*
       Fill detail panel.
    */

    detailPanel.innerHTML = `


        <div class="tools">


            <div>

                <h2>
                    ${x.threat || "Security Alert"}
                </h2>


                <p class="muted">

                    Detailed security-event analysis

                </p>

            </div>


            <button
                onclick="$('detail').classList.add('hidden')">

                Close

            </button>


        </div>



        <div class="detailgrid">


            <!-- =========================================
                 ALERT INFORMATION
                 ========================================= -->

            <div>


                <h3>
                    Alert Information
                </h3>


                <p>

                    <b>
                        Time:
                    </b>

                    ${
                        x.timestamp
                        ? new Date(
                            x.timestamp
                          ).toLocaleString()
                        : "N/A"
                    }

                </p>


                <p>

                    <b>
                        Threat:
                    </b>

                    ${x.threat || "N/A"}

                </p>


                <p>

                    <b>
                        Severity:
                    </b>


                    <i class="sev ${x.severity || "Low"}">

                        ${x.severity || "Low"}

                    </i>

                </p>


                <p>

                    <b>
                        Confidence:
                    </b>

                    ${x.confidence ?? 0}%

                </p>


                <p>

                    <b>
                        Detection Model:
                    </b>

                    ${x.model || "N/A"}

                </p>


                <p>

                    <b>
                        Flow ID:
                    </b>

                    <br>

                    <span class="hash">

                        ${x.flow_id || "N/A"}

                    </span>

                </p>


                <p>

                    <b>
                        Event Hash:
                    </b>

                    <br>

                    <span class="hash">

                        ${x.event_hash || "N/A"}

                    </span>

                </p>


                <p>

                    <b>
                        Previous Hash:
                    </b>

                    <br>

                    <span class="hash">

                        ${x.prev_hash || "N/A"}

                    </span>

                </p>


            </div>



            <!-- =========================================
                 EVIDENCE / RECOMMENDATION
                 ========================================= -->

            <div>


                <h3>
                    Supporting Evidence
                </h3>


                <div class="evidence">

                    ${
                        x.evidence ||
                        "No supporting evidence available."
                    }

                </div>


                <h3>
                    Prevention Recommendation
                </h3>


                <div class="recommend">

                    ${
                        x.recommendation ||
                        "No prevention recommendation available."
                    }

                </div>


            </div>


        </div>

    `;


    /*
       Scroll to top of page.
    */

    window.scrollTo({

        top: 0,

        behavior: "smooth"

    });

}


/* =========================================================
   OVERVIEW
   ========================================================= */

async function load() {

    try {


        const s =
            await api("/api/stats");


        /*
           Overview counters.
        */

        if ($("totalAlerts")) {

            $("totalAlerts").textContent =
                s.alerts;

        }


        if ($("critical")) {

            $("critical").textContent =
                s.critical;

        }


        if ($("high")) {

            $("high").textContent =
                s.high;

        }


        if ($("flows")) {

            $("flows").textContent =
                s.flows;

        }


        /*
           Threat distribution.
        */

        const threats =
            s.threats || [];


        const max =
            Math.max(
                1,
                ...threats.map(
                    x => x.n
                )
            );


        if ($("threats")) {

            $("threats").innerHTML =

                threats.map(x => `

                    <div class="bar">


                        <span>
                            ${x.threat}
                        </span>


                        <div class="track">


                            <div
                                class="fill"
                                style="width:${x.n / max * 100}%">

                            </div>


                        </div>


                        <b>
                            ${x.n}
                        </b>


                    </div>

                `).join("")

                ||

                `

                    <div class="empty">

                        No detections.
                        Use Simulate Flows.

                    </div>

                `;

        }


        /*
           Recent alerts.
        */

        if ($("recent")) {

            const events =
                await api(
                    "/api/events?limit=8"
                );


            $("recent").innerHTML =
                table(events);

        }


    } catch (e) {

        console.error(e);

        toast(
            "Unable to load SOC statistics."
        );

    }

}


/* =========================================================
   ALERTS
   ========================================================= */

async function loadAlerts() {

    try {


        const events =
            await api(
                "/api/events?limit=200"
            );


        if ($("alertTable")) {

            $("alertTable").innerHTML =
                table(events);

        }


    } catch (e) {

        console.error(e);


        if ($("alertTable")) {

            $("alertTable").innerHTML = `

                <div class="empty">

                    Unable to load security alerts.

                </div>

            `;

        }

    }

}


/* =========================================================
   TRAFFIC
   ========================================================= */

async function loadFlows() {

    try {


        const flows =
            await api(
                "/api/flows?limit=200"
            );


        if (!$("flowTable")) {
            return;
        }


        if (!flows.length) {

            $("flowTable").innerHTML = `

                <div class="empty">
                    No flows.
                </div>

            `;

            return;

        }


        $("flowTable").innerHTML = `

            <div class="row head">

                <span>
                    Flow
                </span>

                <span>
                    Source
                </span>

                <span>
                    Destination
                </span>

                <span>
                    Protocol
                </span>

                <span>
                    Bytes
                </span>

            </div>


            ${flows.map(x => `

                <div class="row">


                    <span class="hash">

                        ${x.flow_id}

                    </span>


                    <span>

                        ${x.src_ip}

                    </span>


                    <span>

                        ${x.dst_ip}

                    </span>


                    <span>

                        ${x.protocol}

                    </span>


                    <span>

                        ${Number(
                            x.bytes || 0
                        ).toLocaleString()}

                    </span>


                </div>

            `).join("")}

        `;


    } catch (e) {

        console.error(e);


        if ($("flowTable")) {

            $("flowTable").innerHTML = `

                <div class="empty">

                    Unable to load flows.

                </div>

            `;

        }

    }

}


/* =========================================================
   SECURE LEDGER
   ========================================================= */

async function loadLedger() {

    try {


        const events =
            await api(
                "/api/events?limit=100"
            );


        if ($("ledgerTable")) {

            $("ledgerTable").innerHTML =
                table(events);

        }


    } catch (e) {

        console.error(e);


        if ($("ledgerTable")) {

            $("ledgerTable").innerHTML = `

                <div class="empty">

                    Unable to load ledger.

                </div>

            `;

        }

    }

}


/* =========================================================
   VERIFY LEDGER
   ========================================================= */

async function verifyLedger() {

    try {


        const x =
            await api(
                "/api/verify-ledger"
            );


        if (!$("verify")) {
            return;
        }


        $("verify").className =
            x.valid
                ? "verify"
                : "verify bad";


        $("verify").textContent =

            x.valid

                ?

                `✓ Valid chain — ${x.events_checked} events verified.`

                :

                `✕ Broken chain: ${
                    x.broken_event_ids.join(", ")
                }`;


    } catch (e) {

        console.error(e);

        toast(
            "Ledger verification failed."
        );

    }

}


/* =========================================================
   SIMULATE
   ========================================================= */

async function simulate(
    threat,
    count
) {

    try {


        const x =

            await api(
                "/api/simulate",
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

                            threat:
                                threat || "random",

                            count:
                                count || 1

                        })

                }
            );


        toast(
            `${x.created} flow(s) analysed`
        );


        await load();

        await loadAlerts();


    } catch (e) {

        console.error(e);

        toast(
            "Simulation failed."
        );

    }

}


/* =========================================================
   CSV UPLOAD
   ========================================================= */

async function uploadCSV() {

    const input =
        $("csv");


    if (!input) {
        return;
    }


    const file =
        input.files[0];


    if (!file) {
        return;
    }


    const data =
        new FormData();


    data.append(
        "file",
        file
    );


    try {


        const x =

            await api(
                "/api/upload-csv",
                {

                    method: "POST",

                    body: data

                }
            );


        toast(
            `${x.created} CSV flow(s) processed`
        );


        await load();

        await loadAlerts();


    } catch (e) {

        console.error(e);

        toast(
            "CSV upload failed."
        );

    }

}


/* =========================================================
   PCAP UPLOAD
   ========================================================= */

async function uploadPCAP() {

    const input =
        $("pcap");


    if (!input) {
        return;
    }


    const file =
        input.files[0];


    if (!file) {
        return;
    }


    const data =
        new FormData();


    data.append(
        "file",
        file
    );


    try {


        const x =

            await api(
                "/api/upload-pcap",
                {

                    method: "POST",

                    body: data

                }
            );


        toast(
            `${x.created} PCAP flow(s) processed`
        );


        await load();

        await loadAlerts();


    } catch (e) {

        console.error(e);

        toast(
            e.message ||
            "PCAP upload failed."
        );

    }

}


/* =========================================================
   INITIAL LOAD
   ========================================================= */

load();


/* =========================================================
   AUTO REFRESH
   ========================================================= */

setInterval(
    load,
    5000
);
