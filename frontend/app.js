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

function toast(t) {

    $("toast").textContent = t;

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


    $(id).classList.remove("hidden");


    document
        .querySelectorAll(".nav")
        .forEach(x => {
            x.classList.remove("active");
        });


    if (btn) {
        btn.classList.add("active");
    }


    $("title").textContent = {

        overview: "SOC Overview",

        alerts: "Security Alerts",

        traffic: "Analysed Traffic",

        ledger: "Secure Event Ledger"

    }[id];


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
   TABLE
   ========================================================= */

function table(rows) {


    if (!rows.length) {

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
                    ${new Date(x.timestamp).toLocaleString()}
                </span>


                <span>
                    <b>
                        ${x.threat}
                    </b>
                </span>


                <span>

                    <i class="sev ${x.severity}">
                        ${x.severity}
                    </i>

                </span>


                <span>
                    ${x.confidence}%
                </span>


                <span
                    class="link"
                    onclick='detail(${JSON.stringify(x)})'>

                    ${x.flow_id}

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
   ALERT DETAILS
   ========================================================= */

function detail(x) {


    $("detail").classList.remove("hidden");


    $("detail").innerHTML = `

        <div class="tools">


            <h2>
                ${x.threat}
            </h2>


            <button
                onclick="$('detail').classList.add('hidden')">

                Close

            </button>


        </div>



        <div class="detailgrid">


            <div>


                <p>

                    <b>
                        Severity:
                    </b>

                    <i class="sev ${x.severity}">
                        ${x.severity}
                    </i>

                </p>


                <p>

                    <b>
                        Confidence:
                    </b>

                    ${x.confidence}%

                </p>


                <p>

                    <b>
                        Model:
                    </b>

                    ${x.model}

                </p>


                <p>

                    <b>
                        Flow:
                    </b>

                    <span class="hash">
                        ${x.flow_id}
                    </span>

                </p>


                <p>

                    <b>
                        Event hash:
                    </b>

                    <br>

                    <span class="hash">
                        ${x.event_hash}
                    </span>

                </p>


            </div>



            <div>


                <h3>
                    Supporting Evidence
                </h3>


                <div class="evidence">

                    ${
                        x.evidence ||
                        "No evidence available."
                    }

                </div>



                <h3>
                    Prevention Recommendation
                </h3>


                <div class="recommend">

                    ${
                        x.recommendation ||
                        "No recommendation available."
                    }

                </div>


            </div>


        </div>

    `;

}


/* =========================================================
   OVERVIEW
   ========================================================= */

async function load() {


    try {


        const s =
            await api("/api/stats");


        /*
         IMPORTANT FIX

         Total Alerts counter uses totalAlerts.

         The Alerts TAB uses the separate
         id="alerts".
        */


        $("totalAlerts").textContent =
            s.alerts;


        $("critical").textContent =
            s.critical;


        $("high").textContent =
            s.high;


        $("flows").textContent =
            s.flows;



        /* Threat distribution */


        const max =
            Math.max(
                1,
                ...s.threats.map(x => x.n)
            );


        $("threats").innerHTML =

            s.threats.map(x => `

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



        /* Recent alerts */


        $("recent").innerHTML =

            table(
                await api("/api/events?limit=8")
            );


    } catch (e) {


        console.error(e);


        toast(
            "Unable to load SOC statistics."
        );

    }

}


/* =========================================================
   ALERTS TAB
   ========================================================= */

async function loadAlerts() {


    try {


        const events =
            await api("/api/events?limit=200");


        $("alertTable").innerHTML =
            table(events);


    } catch (e) {


        console.error(e);


        $("alertTable").innerHTML = `

            <div class="empty">

                Unable to load security alerts.

            </div>

        `;

    }

}


/* =========================================================
   TRAFFIC
   ========================================================= */

async function loadFlows() {


    try {


        const f =
            await api("/api/flows?limit=200");


        $("flowTable").innerHTML =

            f.length

            ?

            `

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


                ${f.map(x => `

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
                                x.bytes
                            ).toLocaleString()}
                        </span>

                    </div>

                `).join("")}

            `

            :

            `
                <div class="empty">
                    No flows.
                </div>
            `;


    } catch (e) {


        console.error(e);


        $("flowTable").innerHTML = `

            <div class="empty">
                Unable to load flows.
            </div>

        `;

    }

}


/* =========================================================
   SECURE LEDGER
   ========================================================= */

async function loadLedger() {


    try {


        $("ledgerTable").innerHTML =

            table(
                await api("/api/events?limit=100")
            );


    } catch (e) {


        console.error(e);


        $("ledgerTable").innerHTML = `

            <div class="empty">
                Unable to load ledger.
            </div>

        `;

    }

}


/* =========================================================
   VERIFY LEDGER
   ========================================================= */

async function verifyLedger() {


    try {


        const x =
            await api("/api/verify-ledger");


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
                            threat,
                            count
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


    const f =
        $("csv").files[0];


    if (!f) {
        return;
    }


    const d =
        new FormData();


    d.append(
        "file",
        f
    );


    try {


        const x =

            await api(
                "/api/upload-csv",
                {
                    method: "POST",
                    body: d
                }
            );


        toast(
            `${x.created} CSV flows processed`
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


    const f =
        $("pcap").files[0];


    if (!f) {
        return;
    }


    const d =
        new FormData();


    d.append(
        "file",
        f
    );


    try {


        const x =

            await api(
                "/api/upload-pcap",
                {
                    method: "POST",
                    body: d
                }
            );


        toast(
            `${x.created} PCAP flows processed`
        );


        await load();

        await loadAlerts();


    } catch (e) {


        console.error(e);


        toast(
            e.message
        );

    }

}


/* =========================================================
   INITIAL LOAD
   ========================================================= */

load();


/* Refresh overview every 5 seconds */

setInterval(
    load,
    5000
);
