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
  
  // Elementos da barra de progresso
  const progressBar = document.getElementById('analysis-progress-bar');
  const progressText = document.getElementById('progress-text');
  const progressDetails = document.getElementById('progress-details');

  // Recupera o limite máximo de arquivo do elemento form-text no HTML
  // Força 32MB independentemente do texto do HTML para corrigir a redução para 10MB relatada
  const MAX_FILE_SIZE = 100 * 1024 * 1024; 

  // --- Variáveis para controle da barra de progresso ---
  let progressInterval = null;
  let currentProgress = 0;

  /**
   * Atualiza a barra de progresso e os textos associados.
   * @param {number} percentage - Porcentagem de progresso (0-100).
   * @param {string} text - Texto a ser exibido na barra.
   * @param {string} details - Detalhes do progresso.
   */
  const updateProgress = (percentage, text, details) => {
    if (progressBar) {
      progressBar.style.width = `${percentage}%`;
      progressBar.setAttribute('aria-valuenow', percentage);
    }
    if (progressText) {
      progressText.textContent = text;
    }
    if (progressDetails) {
      progressDetails.textContent = details;
    }
    currentProgress = percentage;
  };

  /**
   * Reseta a barra de progresso para o estado inicial.
   */
  const resetProgress = () => {
    updateProgress(0, 'Iniciando análise...', 'Preparando análise local');
  };

  /**
   * Inicia a simulação de progresso da análise.
   */
  const startProgressSimulation = () => {
    resetProgress();
    let step = 0;
    const steps = [
      { progress: 10, text: 'Analisando...', details: 'Verificando tipo de arquivo e características básicas' },
      { progress: 25, text: 'Processando...', details: 'Extraindo strings e analisando conteúdo' },
      { progress: 40, text: 'Consultando fontes externas...', details: 'Verificando hash em bases de dados de ameaças' },
      { progress: 60, text: 'Analisando com IA...', details: 'Gerando explicação detalhada dos resultados' },
      { progress: 80, text: 'Finalizando...', details: 'Consolidando veredito final' }
    ];

    progressInterval = setInterval(() => {
      if (step < steps.length) {
        const currentStep = steps[step];
        updateProgress(currentStep.progress, currentStep.text, currentStep.details);
        step++;
      } else {
        // Mantém em 90% até completar
        updateProgress(90, 'Quase pronto...', 'Aguardando resposta final');
        clearInterval(progressInterval);
        progressInterval = null;
      }
    }, 1500); // Atualiza a cada 1.5 segundos
  };

  /**
   * Para a simulação de progresso.
   */
  const stopProgressSimulation = () => {
    if (progressInterval) {
      clearInterval(progressInterval);
      progressInterval = null;
    }
  };

  /**
   * Completa o progresso (chamado quando a análise termina com sucesso).
   */
  const completeProgress = () => {
    stopProgressSimulation();
    updateProgress(100, 'Concluído!', 'Análise finalizada com sucesso');
    // Pequena pausa antes de redirecionar
    setTimeout(() => {
      // O redirecionamento será feito pelo código existente
    }, 500);
  };

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
      startProgressSimulation();
    } else {
      if (analysisPanels) analysisPanels.style.display = 'block';
      if (loadingSpinner) loadingSpinner.style.display = 'none';
      stopProgressSimulation();
      resetProgress();
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
    
    // Obtém o provedor selecionado
    const providerSelect = document.getElementById('ai-provider-malware'); // ID corrigido conforme index.html
    const provider = providerSelect ? providerSelect.value : 'groq';
    formData.append('ai_provider', provider);

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
        // Completa o progresso antes de redirecionar
        completeProgress();
        // Pequena pausa para mostrar o progresso completo
        setTimeout(() => {
             window.location.href = `/results/${data.result_id}`;
        }, 500);
      } else {
        showLoading(false);
        window.showAlert('Análise concluída, mas nenhum ID de resultado foi retornado.', 'warning');
      }
    })
    .catch(error => {
      console.error('Erro na análise de arquivo:', error);
      showLoading(false);
      window.showAlert(`Erro ao enviar arquivo: ${error.message}`, 'danger');
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

    // Obtém o provedor selecionado (reutilizando o mesmo select do arquivo para simplicidade na UI atual)
    const providerSelect = document.getElementById('ai-provider-malware'); 
    const provider = providerSelect ? providerSelect.value : 'groq';

    const requestBody = { url: url, ai_provider: provider };

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
        completeProgress();
        setTimeout(() => {
          window.location.href = `/results/${data.result_id}`;
        }, 800);
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
