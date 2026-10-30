/**
 * CodeGuard Lite — Automated Code Reviewer & Security Scanner
 * Frontend Interactive Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDragAndDrop();
  initSampleCodeLoaders();
  initScanForm();
  initResultsFilters();
  initSourceInspector();
});

/* ==========================================================================
   1. Tab Switching (Upload File vs Paste Code)
   ========================================================================== */
function initTabs() {
  const tabUpload = document.getElementById('tab-upload');
  const tabPaste = document.getElementById('tab-paste');
  const uploadPanel = document.getElementById('upload-panel');
  const pastePanel = document.getElementById('paste-panel');

  if (!tabUpload || !tabPaste) return;

  tabUpload.addEventListener('click', () => {
    tabUpload.classList.add('active');
    tabPaste.classList.remove('active');
    uploadPanel.style.display = 'block';
    pastePanel.style.display = 'none';
  });

  tabPaste.addEventListener('click', () => {
    tabPaste.classList.add('active');
    tabUpload.classList.remove('active');
    uploadPanel.style.display = 'none';
    pastePanel.style.display = 'block';
  });
}

/* ==========================================================================
   2. Drag-and-Drop & File Upload Handling
   ========================================================================== */
function initDragAndDrop() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const btnBrowse = document.getElementById('btn-browse-file');
  const fileBadge = document.getElementById('file-badge');
  const fileNameDisplay = document.getElementById('file-name-display');
  const fileSizeDisplay = document.getElementById('file-size-display');
  const btnRemoveFile = document.getElementById('btn-remove-file');

  if (!dropzone || !fileInput) return;

  // Click on Browse Button or Dropzone triggers hidden file input
  if (btnBrowse) {
    btnBrowse.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });
  }

  dropzone.addEventListener('click', () => {
    fileInput.click();
  });

  // Drag Events
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  // Drop Event
  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleSelectedFile(files[0]);
    }
  });

  // File Input Change
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleSelectedFile(fileInput.files[0]);
    }
  });

  // Remove File Button
  if (btnRemoveFile) {
    btnRemoveFile.addEventListener('click', (e) => {
      e.stopPropagation();
      clearSelectedFile();
    });
  }

  function handleSelectedFile(file) {
    // Validate .py extension
    if (!file.name.toLowerCase().endsWith('.py')) {
      alert('Security Validation: Only Python source files (.py) are permitted.');
      clearSelectedFile();
      return;
    }

    // Validate size (2MB max)
    if (file.size > 2 * 1024 * 1024) {
      alert('File Too Large: Uploaded file exceeds the maximum allowed 2MB limit.');
      clearSelectedFile();
      return;
    }

    // Assign file to input element if dropped
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    fileInput.files = dataTransfer.files;

    // Display File Badge
    const sizeKB = (file.size / 1024).toFixed(1);
    fileNameDisplay.textContent = file.name;
    fileSizeDisplay.textContent = `${sizeKB} KB — Ready for static AST review`;
    fileBadge.style.display = 'flex';
  }

  function clearSelectedFile() {
    fileInput.value = '';
    if (fileBadge) fileBadge.style.display = 'none';
  }
}

/* ==========================================================================
   3. Sample Code Loader
   ========================================================================== */
function initSampleCodeLoaders() {
  const btnLoadSample = document.getElementById('btn-load-sample');
  const btnLoadSampleHero = document.getElementById('btn-load-sample-hero');
  const codeInput = document.getElementById('code-input');
  const tabPaste = document.getElementById('tab-paste');
  const tabUpload = document.getElementById('tab-upload');
  const uploadPanel = document.getElementById('upload-panel');
  const pastePanel = document.getElementById('paste-panel');

  function loadSample() {
    fetch('/api/sample-code')
      .then(res => res.json())
      .then(data => {
        if (data.success && codeInput) {
          codeInput.value = data.code;
          const filenameCustom = document.getElementById('filename-custom');
          if (filenameCustom) filenameCustom.value = data.filename;

          // Switch to paste tab
          if (tabPaste && tabUpload && uploadPanel && pastePanel) {
            tabPaste.classList.add('active');
            tabUpload.classList.remove('active');
            uploadPanel.style.display = 'none';
            pastePanel.style.display = 'block';
          }

          // Smooth scroll to scanner
          const scannerSection = document.getElementById('scanner-section');
          if (scannerSection) {
            scannerSection.scrollIntoView({ behavior: 'smooth' });
          }
        }
      })
      .catch(err => {
        console.error('Error fetching sample code:', err);
      });
  }

  if (btnLoadSample) {
    btnLoadSample.addEventListener('click', loadSample);
  }

  if (btnLoadSampleHero) {
    btnLoadSampleHero.addEventListener('click', loadSample);
  }
}

/* ==========================================================================
   4. Scan Submission & Cyber Progress Bar Animation
   ========================================================================== */
function initScanForm() {
  const form = document.getElementById('scan-form');
  const progressModal = document.getElementById('progress-modal');
  const progressBarFill = document.getElementById('progress-bar-fill');
  const statusText = document.getElementById('progress-status-text');
  const fileInput = document.getElementById('file-input');
  const codeInput = document.getElementById('code-input');

  if (!form || !progressModal) return;

  const steps = [
    { percent: 20, id: 'step-1', text: 'Tokenizing source code into Abstract Syntax Tree...' },
    { percent: 40, id: 'step-2', text: 'Inspecting dangerous call nodes (eval / exec)...' },
    { percent: 65, id: 'step-3', text: 'Auditing module namespaces & wildcard imports...' },
    { percent: 85, id: 'step-4', text: 'Verifying PEP 257 docstrings for functions & classes...' },
    { percent: 100, id: 'step-5', text: 'Synthesizing security audit metrics & report...' }
  ];

  form.addEventListener('submit', (e) => {
    e.preventDefault();

    // Check if file or code is provided
    const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
    const hasCode = codeInput && codeInput.value.trim().length > 0;

    if (!hasFile && !hasCode) {
      alert('Please upload a Python (.py) file or paste Python code to scan.');
      return;
    }

    // Show Progress Modal
    progressModal.style.display = 'flex';
    let currentStepIdx = 0;

    // Start progress animation
    const progressInterval = setInterval(() => {
      if (currentStepIdx < steps.length) {
        const step = steps[currentStepIdx];
        progressBarFill.style.width = `${step.percent}%`;
        statusText.textContent = step.text;

        // Update step indicators
        for (let i = 0; i <= currentStepIdx; i++) {
          const el = document.getElementById(steps[i].id);
          if (el) {
            el.className = 'progress-step active';
            const icon = el.querySelector('i');
            if (icon && i < currentStepIdx) {
              icon.className = 'fa-solid fa-circle-check';
              icon.style.color = 'var(--neon-green)';
            }
          }
        }
        currentStepIdx++;
      }
    }, 250);

    // Send FormData via Fetch
    const formData = new FormData(form);

    fetch('/scan', {
      method: 'POST',
      body: formData,
      headers: {
        'X-Requested-With': 'XMLHttpRequest'
      }
    })
    .then(async (res) => {
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Static analysis failed.');
      }
      return data;
    })
    .then((data) => {
      // Ensure all steps complete visually
      setTimeout(() => {
        clearInterval(progressInterval);
        progressBarFill.style.width = '100%';
        statusText.textContent = 'Scan complete! Redirecting to audit dashboard...';

        // Redirect to results
        setTimeout(() => {
          window.location.href = data.redirect_url;
        }, 300);
      }, 900);
    })
    .catch((err) => {
      clearInterval(progressInterval);
      progressModal.style.display = 'none';
      alert(`Scan Error: ${err.message}`);
    });
  });
}

/* ==========================================================================
   5. Results Dashboard: Severity Filtering & Live Search
   ========================================================================== */
function initResultsFilters() {
  const filterPills = document.querySelectorAll('.filter-pill');
  const searchInput = document.getElementById('issue-search-input');
  const issueCards = document.querySelectorAll('.issue-card');

  if (!filterPills.length || !issueCards.length) return;

  let activeSeverity = 'all';
  let searchQuery = '';

  function applyFilters() {
    issueCards.forEach(card => {
      const cardSeverity = card.getAttribute('data-severity');
      const cardText = card.getAttribute('data-text') || '';

      const matchesSeverity = (activeSeverity === 'all') || (cardSeverity === activeSeverity);
      const matchesSearch = (!searchQuery) || (cardText.includes(searchQuery));

      if (matchesSeverity && matchesSearch) {
        card.style.display = 'block';
      } else {
        card.style.display = 'none';
      }
    });
  }

  // Filter Pills Click
  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      activeSeverity = pill.getAttribute('data-filter');
      applyFilters();
    });
  });

  // Search Input
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      applyFilters();
    });
  }
}

/* ==========================================================================
   6. Full Source Code Inspector Accordion
   ========================================================================== */
function initSourceInspector() {
  const toggleBtn = document.getElementById('btn-toggle-inspector');
  const inspectorBody = document.getElementById('inspector-body');

  if (!toggleBtn || !inspectorBody) return;

  toggleBtn.addEventListener('click', () => {
    const isOpen = inspectorBody.style.display === 'block';
    if (isOpen) {
      inspectorBody.style.display = 'none';
      toggleBtn.classList.remove('open');
    } else {
      inspectorBody.style.display = 'block';
      toggleBtn.classList.add('open');
    }
  });

  // Wire issue card location clicks to jump to source code line
  const locationBadges = document.querySelectorAll('.issue-location');
  locationBadges.forEach(badge => {
    badge.style.cursor = 'pointer';
    badge.title = 'Click to view highlighted line in code inspector';
    badge.addEventListener('click', () => {
      const match = badge.textContent.match(/Line\s+(\d+)/);
      if (match && match[1]) {
        const lineNum = match[1];
        // Open inspector if closed
        inspectorBody.style.display = 'block';
        toggleBtn.classList.add('open');

        const targetRow = document.getElementById(`src-line-${lineNum}`);
        if (targetRow) {
          targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
          targetRow.style.transition = 'outline 0.3s ease';
          targetRow.style.outline = '2px solid var(--neon-green)';
          setTimeout(() => {
            targetRow.style.outline = 'none';
          }, 2000);
        }
      }
    });
  });
}

