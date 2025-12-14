// Aguarda o DOM estar completamente carregado antes de executar o script.
document.addEventListener('DOMContentLoaded', () => {

  // --- Seleção dos Elementos da UI ---
  const fileForm = document.getElementById('file-form');
  const urlForm = document.getElementById('url-form');
  const fileInput = document.getElementById('file-input');
  const urlInput = document.getElementById('url-input');

  const loadingSpinner = document.getElementById('loading-spinner');
  const analysisPanels = document.getElementById('analysis-panels');
  const indexGeneralAlertArea = document.getElementById('general-alert-area'); // Específico para index.html

  // Recupera o limite máximo de arquivo do elemento form-text no HTML
  // Força 32MB independentemente do texto do HTML para corrigir a redução para 10MB relatada
  const MAX_FILE_SIZE = 100 * 1024 * 1024; 

  // --- Funções de Manipulação da UI ---

  /**
   * Exibe um alerta Bootstrap em uma área de alertas especificada.
   * Por padrão, usa a área geral do index.html ou a do settings.html se existir.
   * @param {string} message - A mensagem a ser exibida.
   * @param {string} type - O tipo de alerta (e.g., 'success', 'danger', 'warning', 'info').
   * @param {HTMLElement} [targetArea] - A área onde o alerta será exibido.
   */
  window.showAlert = (message, type = 'danger', targetArea) => {
    // Tenta usar a área de alerta do index.html, depois a do settings.html
    const alertArea = targetArea || indexGeneralAlertArea || document.getElementById('alert-placeholder');
    if (!alertArea) {
        console.error('Nenhuma área de alerta encontrada para exibir a mensagem.');
        return;
    }

    const alertHtml = `
      <div class="alert alert-${type} alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    `;
    alertArea.innerHTML = alertHtml;
    // Remove o alerta após 5 segundos
    setTimeout(() => {
      const alertElement = alertArea.querySelector('.alert');
      if (alertElement) {
        new bootstrap.Alert(alertElement).close();
      }
    }, 5000);
  };

  /**
   * Alterna a visibilidade entre os painéis de análise e o spinner de carregamento.
   * @param {boolean} show - True para mostrar o spinner, false para mostrar os painéis.
   */
  const showLoading = (show) => {
    if (show) {
      if (indexGeneralAlertArea) indexGeneralAlertArea.innerHTML = ''; // Limpa alertas ao carregar na página index
      if (analysisPanels) analysisPanels.style.display = 'none';
      if (loadingSpinner) loadingSpinner.style.display = 'block';
    } else {
      if (analysisPanels) analysisPanels.style.display = 'block';
      if (loadingSpinner) loadingSpinner.style.display = 'none';
    }
  };

  // --- Funções de Lógica de Análise ---

  /**
   * Lida com o envio do formulário de análise de arquivo.
   * @param {Event} event - O evento de submit do formulário.
   */
  const handleFileAnalysis = (event) => {
    event.preventDefault(); // Previne o recarregamento da página

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
      window.showAlert('Por favor, selecione um arquivo para analisar.');
      return;
    }

    const file = fileInput.files[0];

    // Validação de tamanho do arquivo
    if (file.size > MAX_FILE_SIZE) {
        window.showAlert(`O arquivo "${file.name}" excede o tamanho máximo permitido de ${MAX_FILE_SIZE / (1024 * 1024)} MB.`);
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    showLoading(true);

    fetch('/api/analyze/file', {
      method: 'POST',
      body: formData,
    })
    .then(response => {
        if (!response.ok) {
            // Se a resposta não for OK, tenta extrair o erro do corpo JSON
            return response.json().then(err => {
                throw new Error(err.error || `Erro do servidor: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
      if (data.result_id) {
        // Redireciona para a página de resultados em caso de sucesso.
        window.location.href = `/results/${data.result_id}`;
      } else {
        // Se não houver result_id, trata como um erro.
        throw new Error(data.error || 'Ocorreu um erro desconhecido no servidor.');
      }
    })
    .catch(error => {
      showLoading(false);
      window.showAlert(`Erro na análise do arquivo: ${error.message}`);
    });
  };

  /**
   * Lida com o envio do formulário de análise de URL.
   * @param {Event} event - O evento de submit do formulário.
   */
  const handleUrlAnalysis = (event) => {
    event.preventDefault();

    let url = urlInput ? urlInput.value.trim() : '';
    if (!url) {
      window.showAlert('Por favor, insira uma URL para analisar.');
      return;
    }

    // Adiciona https:// automaticamente se um protocolo não estiver presente
    if (!/^https?:\/\//i.test(url)) {
      url = 'https://' + url;
    }

    showLoading(true);

    const requestBody = { url: url };

    fetch('/api/analyze/url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => {
                throw new Error(err.error || `Erro do servidor: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
      if (data.result_id) {
        window.location.href = `/results/${data.result_id}`;
      } else {
        throw new Error(data.error || 'Ocorreu um erro desconhecido no servidor.');
      }
    })
    .catch(error => {
      showLoading(false);
      window.showAlert(`Erro na análise da URL: ${error.message}`);
    });
  };

  // --- Adiciona os Event Listeners aos Formulários ---
  if (fileForm) {
    fileForm.addEventListener('submit', handleFileAnalysis);
  }
  if (urlForm) {
    urlForm.addEventListener('submit', handleUrlAnalysis);
  }
});
