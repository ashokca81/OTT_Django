class Modal {
    constructor(options = {}) {
        this.options = {
            preventScroll: true,
            closeOnEscape: true,
            closeOnOverlayClick: true,
            ...options
        };
        
        this.isOpen = false;
        this.setupModal();
    }

    setupModal() {
        // Create modal elements
        this.overlay = document.createElement('div');
        this.overlay.className = 'modal-overlay';
        
        this.container = document.createElement('div');
        this.container.className = 'modal-container';
        
        this.overlay.appendChild(this.container);
        
        // Event listeners
        if (this.options.closeOnEscape) {
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.isOpen) {
                    this.close();
                }
            });
        }
        
        if (this.options.closeOnOverlayClick) {
            this.overlay.addEventListener('click', (e) => {
                if (e.target === this.overlay) {
                    this.close();
                }
            });
        }
    }

    setContent(content) {
        this.container.innerHTML = content;
    }

    open() {
        if (!this.isOpen) {
            document.body.appendChild(this.overlay);
            if (this.options.preventScroll) {
                document.body.classList.add('modal-open');
            }
            this.isOpen = true;
            
            // Ensure modal is centered
            this.container.style.opacity = '0';
            requestAnimationFrame(() => {
                this.container.style.opacity = '1';
            });
        }
    }

    close() {
        if (this.isOpen) {
            document.body.removeChild(this.overlay);
            if (this.options.preventScroll) {
                document.body.classList.remove('modal-open');
            }
            this.isOpen = false;
        }
    }

    // Helper method to create modal content structure
    static createModalContent({ title, body, footer }) {
        return `
            <div class="modal-header">
                <h5 class="modal-title">${title}</h5>
                <button type="button" class="modal-close" aria-label="Close">&times;</button>
            </div>
            <div class="modal-body">${body}</div>
            ${footer ? `<div class="modal-footer">${footer}</div>` : ''}
        `;
    }
}

// Example usage:
/*
const modal = new Modal();
modal.setContent(Modal.createModalContent({
    title: 'Modal Title',
    body: 'Modal content goes here',
    footer: '<button class="btn btn-primary">Save</button>'
}));
modal.open();
*/ 