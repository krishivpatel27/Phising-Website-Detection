document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const input = document.getElementById('url-input');
    const btn = document.getElementById('scan-btn');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.querySelector('.spinner');
    const resultsSection = document.getElementById('results-section');
    
    // Result elements
    const badge = document.getElementById('prediction-badge');
    const confidenceVal = document.getElementById('confidence-value');
    const riskVal = document.getElementById('risk-value');
    const reasonsList = document.getElementById('reasons-list');
    const confidenceWrapper = document.querySelector('.confidence-wrapper');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = input.value.trim();
        if (!url) return;

        // Set Loading state
        btn.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        resultsSection.classList.add('hidden');

        try {
            // Give a 1s fake delay for "scanning" animation effect
            await new Promise(r => setTimeout(r, 1000));

            const response = await fetch('http://127.0.0.1:5000/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) throw new Error('Network response was not ok');
            
            const data = await response.json();
            
            displayResults(data);
        } catch (error) {
            console.error('Error:', error);
            alert('Failed to connect to the backend. Make sure the Flask server is running.');
        } finally {
            // Remove Loading state
            btn.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    });

    function displayResults(data) {
        // Remove existing classes
        badge.className = 'badge';
        confidenceWrapper.className = 'confidence-wrapper';
        riskVal.className = '';
        reasonsList.className = '';
        
        // Update Prediction
        badge.textContent = data.prediction;
        if (data.prediction === 'Phishing') {
            badge.classList.add('phishing');
            confidenceWrapper.classList.add('phishing-confidence');
            reasonsList.classList.remove('safe-reasons');
        } else {
            badge.classList.add('safe');
            confidenceWrapper.classList.add('safe-confidence');
            reasonsList.classList.add('safe-reasons');
        }

        // Update Confidence
        confidenceVal.textContent = data.confidence;

        // Update Risk Level
        riskVal.textContent = data.risk_level;
        riskVal.classList.add(`risk-${data.risk_level}`);

        // Update Reasons
        reasonsList.innerHTML = '';
        data.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            reasonsList.appendChild(li);
        });

        // Show results
        resultsSection.classList.remove('hidden');
        resultsSection.style.display = 'block';
    }
});
