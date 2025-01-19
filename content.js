document.querySelector('form').addEventListener('submit', async function(event) {

    event.preventDefault();

    alert("Loading ...");
    
    const url = document.querySelector('input[name="url"]').value;
    
    const api = '18b64077d789015fc5ce6f08e2a65759c7a0146d83ec8c1d61793a1553c7abde';
    
    const virusTotal = 'https://www.virustotal.com/api/v3/urls';
    
    const headers = new Headers({
        "Accept": "application/json",
        "x-apikey": api,
        "Content-Type": "application/x-www-form-urlencoded"
    });

    const answer = await fetch(virusTotal, {
        method: 'POST',
        headers: headers,
        body: `url=${encodeURIComponent(url)}`,
    });

    const data = await answer.json();

    if (data.error && data.error.code === "InvalidArgumentError") {
        alert("Error! Invalid URL, please try again!");
        document.querySelector('input[name="url"]').value = '';
        return;
    }
    
    else if (data.error) {
        console.error('API Error:', data.error);
        alert("Error! While checking the URL. Please try again later!");
        return;
    }
    
    const reportUrl = `https://www.virustotal.com/api/v3/analyses/${data.data.id}`;
    
    const repAnswer = await fetch(reportUrl, { headers });
    
    const repData = await repAnswer.json();

    if (repData.data.attributes.stats.malicious > 0) {
        window.location.href = 'NotSafe.html';
        document.querySelector('input[name="url"]').value = '';
    }

    else {
        window.location.href = 'Safe.html';
        document.querySelector('input[name="url"]').value = '';
    }
});