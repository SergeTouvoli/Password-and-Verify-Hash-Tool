document.addEventListener("DOMContentLoaded", () => {
    const message = document.getElementById('message');
    const passwordInput = document.getElementById('passwordInput');
    const selectTypeHash = document.getElementById('hashTypeSelect');
    const resultInput = document.getElementById('hashResult');
    const copyButton = document.getElementById('copyResult');

    selectTypeHash.addEventListener('change', async function (event) {
        event.preventDefault();

        const typeHash = selectTypeHash.value;
        passwordInput.disabled = typeHash === "";

        if(typeHash !== ""){
            if (passwordInput.value !== "") {
                hashText();
            }
        }

      
    });

    copyButton.addEventListener('click', function () {
        copyHash();
    })

    passwordInput.addEventListener('keyup', async function (event) {
        event.preventDefault();
        hashText();
    });

    const form = document.querySelector('#verif-hash form');
    form.addEventListener('submit', async function (event) {
        event.preventDefault();

        const url = window.location.origin + '/password_hash/api/verif-hash';
        const formData = new FormData(form);
        const message = form.querySelector('div.message');

        try {

            const response = await fetch(url, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            //console.log(data)

            if (data.success) {
                message.classList.add('text-success');
                message.textContent = data.msg
            } else {
                message.classList.add('text-danger');
                message.textContent = data.msg;
            }

        } catch(error) {
            console.error(error);
        }
    });




    function copyHash() {
    
        resultInput.select();
        resultInput.setSelectionRange(0, 99999); 
    
        document.execCommand('copy');
    
        window.getSelection().removeAllRanges();
        message.classList.add('text-success');
        message.textContent = 'Le résultat a été copié dans le presse-papiers.';
    }

    async function hashText() {
        const typeHash = selectTypeHash.value;
        const hashText = passwordInput.value;
        
        message.textContent = "";

        if(!typeHash){
            message.classList.add('text-danger');
            message.textContent = 'Veuillez choisir un type de hachage';
            return;
        }

        if (!hashText) {
            message.classList.add('text-danger');
            message.textContent = 'Veuillez saisir un texte à hasher';
            return;
        }

        const url = window.location.origin + '/password_hash/api/hash-text';
        const formData = new FormData();
        formData.append('hash_type', typeHash);
        formData.append('hash_text', hashText);

        try {
            const response = await fetch(url, {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            if (data.success) {
                resultInput.value = data.result;
                copyButton.disabled = false;
            } else {
                message.classList.add('text-danger');
                message.textContent = data.error;
            }
        } catch (error) {
            console.error('Error:', error.message);
        }
    }
});
