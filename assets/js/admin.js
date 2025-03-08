/**
 * Font Protection for Media Offloader - Admin JavaScript
 */
(function($) {
    'use strict';
    
    // Initialize once the DOM is fully loaded
    $(document).ready(function() {
        // Initialize tooltips
        initTooltips();
        
        // Force restore button
        $('#fontprotect-force-restore, .fontprotect-force-restore').on('click', function(e) {
            e.preventDefault();
            
            if (confirm(fontProtectData.i18n.confirmRestore)) {
                showLoadingOverlay();
                
                $.ajax({
                    url: fontProtectData.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'fontprotect_force_restore',
                        nonce: fontProtectData.nonce
                    },
                    success: function(response) {
                        hideLoadingOverlay();
                        
                        if (response.success) {
                            showMessage('success', response.data.message);
                            setTimeout(function() {
                                window.location.reload();
                            }, 2000);
                        } else {
                            showMessage('error', response.data.message);
                        }
                    },
                    error: function() {
                        hideLoadingOverlay();
                        showMessage('error', 'An unexpected error occurred. Please try again.');
                    }
                });
            }
        });
        
        // Clear cache button
        $('#fontprotect-clear-cache, .fontprotect-clear-cache').on('click', function(e) {
            e.preventDefault();
            
            if (confirm(fontProtectData.i18n.confirmClearCache)) {
                showLoadingOverlay();
                
                $.ajax({
                    url: fontProtectData.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'fontprotect_clear_cache',
                        nonce: fontProtectData.nonce
                    },
                    success: function(response) {
                        hideLoadingOverlay();
                        
                        if (response.success) {
                            showMessage('success', response.data.message);
                        } else {
                            showMessage('error', response.data.message);
                        }
                    },
                    error: function() {
                        hideLoadingOverlay();
                        showMessage('error', 'An unexpected error occurred. Please try again.');
                    }
                });
            }
        });
        
        // Export logs button
        $('#fontprotect-export-logs').on('click', function(e) {
            e.preventDefault();
            
            $.ajax({
                url: fontProtectData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'fontprotect_export_logs',
                    nonce: fontProtectData.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Create a download link
                        downloadCSV(response.data.csv, response.data.filename);
                    } else {
                        showMessage('error', response.data.message);
                    }
                },
                error: function() {
                    showMessage('error', 'An unexpected error occurred. Please try again.');
                }
            });
        });
        
        // Clear logs button
        $('#fontprotect-clear-logs').on('click', function(e) {
            e.preventDefault();
            
            if (confirm('Are you sure you want to clear all logs? This action cannot be undone.')) {
                showLoadingOverlay();
                
                $.ajax({
                    url: fontProtectData.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'fontprotect_clear_logs',
                        nonce: fontProtectData.nonce
                    },
                    success: function(response) {
                        hideLoadingOverlay();
                        
                        if (response.success) {
                            showMessage('success', response.data.message);
                            setTimeout(function() {
                                window.location.reload();
                            }, 1500);
                        } else {
                            showMessage('error', response.data.message);
                        }
                    },
                    error: function() {
                        hideLoadingOverlay();
                        showMessage('error', 'An unexpected error occurred. Please try again.');
                    }
                });
            }
        });
        
        // Scan theme button
        $('#fontprotect-scan-theme').on('click', function(e) {
            e.preventDefault();
            
            showLoadingOverlay();
            
            $.ajax({
                url: fontProtectData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'fontprotect_scan_theme',
                    nonce: fontProtectData.nonce
                },
                success: function(response) {
                    hideLoadingOverlay();
                    
                    if (response.success) {
                        showScanResults(response.data.results);
                    } else {
                        showMessage('error', response.data.message);
                    }
                },
                error: function() {
                    hideLoadingOverlay();
                    showMessage('error', 'An unexpected error occurred. Please try again.');
                }
            });
        });
        
        // Generate CSS button
        $('#fontprotect-generate-css').on('click', function(e) {
            e.preventDefault();
            
            showLoadingOverlay();
            
            $.ajax({
                url: fontProtectData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'fontprotect_generate_css',
                    nonce: fontProtectData.nonce
                },
                success: function(response) {
                    hideLoadingOverlay();
                    
                    if (response.success) {
                        showCSSModal(response.data.css);
                    } else {
                        showMessage('error', response.data.message);
                    }
                },
                error: function() {
                    hideLoadingOverlay();
                    showMessage('error', 'An unexpected error occurred. Please try again.');
                }
            });
        });
        
        // Copy system info button
        $('#fontprotect-copy-system-info').on('click', function(e) {
            e.preventDefault();
            
            var systemInfo = $('#fontprotect-system-info').val();
            
            // Create a temporary textarea element
            var textarea = document.createElement('textarea');
            textarea.value = systemInfo;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'absolute';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            
            // Select and copy the text
            textarea.select();
            document.execCommand('copy');
            
            // Remove the temporary element
            document.body.removeChild(textarea);
            
            // Show success message
            $(this).text('Copied!');
            setTimeout(function() {
                $('#fontprotect-copy-system-info').text('Copy to Clipboard');
            }, 2000);
        });
    });
    
    /**
     * Initialize tooltips
     */
    function initTooltips() {
        $('.fontprotect-tooltip').each(function() {
            $(this).attr('title', $(this).data('tooltip'));
        });
    }
    
    /**
     * Show loading overlay
     */
    function showLoadingOverlay() {
        if ($('#fontprotect-loading-overlay').length === 0) {
            $('body').append('<div id="fontprotect-loading-overlay"><div class="fontprotect-spinner"></div><div class="fontprotect-loading-text">' + fontProtectData.i18n.loading + '</div></div>');
        }
        
        $('#fontprotect-loading-overlay').fadeIn(200);
    }
    
    /**
     * Hide loading overlay
     */
    function hideLoadingOverlay() {
        $('#fontprotect-loading-overlay').fadeOut(200, function() {
            $(this).remove();
        });
    }
    
    /**
     * Show message
     */
    function showMessage(type, message) {
        var icon = 'dashicons-info';
        var typeClass = 'notice-info';
        var prefix = '';
        
        if (type === 'success') {
            icon = 'dashicons-yes';
            typeClass = 'notice-success';
            prefix = fontProtectData.i18n.success + ' ';
        } else if (type === 'error') {
            icon = 'dashicons-no';
            typeClass = 'notice-error';
            prefix = fontProtectData.i18n.error + ' ';
        } else if (type === 'warning') {
            icon = 'dashicons-warning';
            typeClass = 'notice-warning';
        }
        
        var $message = $('<div class="notice ' + typeClass + ' is-dismissible fontprotect-notice"><p><span class="dashicons ' + icon + '"></span> ' + prefix + message + '</p><button type="button" class="notice-dismiss"></button></div>');
        
        // Remove existing notices
        $('.fontprotect-notice').remove();
        
        // Add the new notice at the top of the page
        $('#wpbody-content').prepend($message);
        
        // Make notices dismissible
        $message.find('.notice-dismiss').on('click', function() {
            $(this).parent().fadeOut(200, function() {
                $(this).remove();
            });
        });
        
        // Auto-dismiss after 5 seconds for success messages
        if (type === 'success') {
            setTimeout(function() {
                $message.fadeOut(200, function() {
                    $(this).remove();
                });
            }, 5000);
        }
    }
    
    /**
     * Download CSV
     */
    function downloadCSV(csv, filename) {
        var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        var link = document.createElement('a');
        
        if (navigator.msSaveBlob) { // IE 10+
            navigator.msSaveBlob(blob, filename);
        } else {
            var url = URL.createObjectURL(blob);
            link.href = url;
            link.style.display = 'none';
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            setTimeout(function() {
                URL.revokeObjectURL(url);
            }, 100);
        }
    }
    
    /**
     * Show scan results
     */
    function showScanResults(results) {
        // Create modal
        var $modal = $('<div id="fontprotect-modal" class="fontprotect-modal"><div class="fontprotect-modal-content"><span class="fontprotect-modal-close">&times;</span><h2>Theme Font Scan Results</h2><div id="fontprotect-scan-results"></div></div></div>');
        
        // Add results to modal
        var $results = $modal.find('#fontprotect-scan-results');
        
        if (results.font_references.length === 0) {
            $results.append('<p>No font references found in your theme.</p>');
        } else {
            $results.append('<p>Found ' + results.font_references.length + ' font references in your theme:</p>');
            
            var $table = $('<table class="widefat striped"><thead><tr><th>File</th><th>Line</th><th>Reference</th></tr></thead><tbody></tbody></table>');
            
            $.each(results.font_references, function(i, reference) {
                $table.find('tbody').append('<tr><td>' + reference.file + '</td><td>' + reference.line + '</td><td>' + reference.reference + '</td></tr>');
            });
            
            $results.append($table);
            
            if (results.font_references.length > 0) {
                $results.append('<div class="fontprotect-modal-actions"><button id="fontprotect-fix-refs" class="button button-primary">Fix These References</button></div>');
            }
        }
        
        // Add modal to body
        $('body').append($modal);
        
        // Show modal
        $modal.fadeIn(200);
        
        // Close button
        $modal.find('.fontprotect-modal-close').on('click', function() {
            $modal.fadeOut(200, function() {
                $(this).remove();
            });
        });
        
        // Close when clicking outside the modal
        $(window).on('click', function(e) {
            if ($(e.target).is($modal)) {
                $modal.fadeOut(200, function() {
                    $(this).remove();
                });
            }
        });
        
        // Fix references button
        $modal.find('#fontprotect-fix-refs').on('click', function() {
            showLoadingOverlay();
            
            $.ajax({
                url: fontProtectData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'fontprotect_fix_references',
                    nonce: fontProtectData.nonce,
                    references: results.font_references
                },
                success: function(response) {
                    hideLoadingOverlay();
                    
                    if (response.success) {
                        $modal.fadeOut(200, function() {
                            $(this).remove();
                        });
                        
                        showMessage('success', response.data.message);
                    } else {
                        showMessage('error', response.data.message);
                    }
                },
                error: function() {
                    hideLoadingOverlay();
                    showMessage('error', 'An unexpected error occurred. Please try again.');
                }
            });
        });
    }
    
    /**
     * Show CSS modal
     */
    function showCSSModal(css) {
        // Create modal
        var $modal = $('<div id="fontprotect-modal" class="fontprotect-modal"><div class="fontprotect-modal-content"><span class="fontprotect-modal-close">&times;</span><h2>Generated Font CSS Fix</h2><div id="fontprotect-css-content"></div></div></div>');
        
        // Add CSS to modal
        var $content = $modal.find('#fontprotect-css-content');
        
        $content.append('<p>Add this CSS to your theme\'s style.css file or in the Customizer:</p>');
        $content.append('<textarea rows="15" readonly>' + css + '</textarea>');
        $content.append('<div class="fontprotect-modal-actions"><button id="fontprotect-copy-css" class="button button-primary">Copy to Clipboard</button></div>');
        
        // Add modal to body
        $('body').append($modal);
        
        // Show modal
        $modal.fadeIn(200);
        
        // Close button
        $modal.find('.fontprotect-modal-close').on('click', function() {
            $modal.fadeOut(200, function() {
                $(this).remove();
            });
        });
        
        // Close when clicking outside the modal
        $(window).on('click', function(e) {
            if ($(e.target).is($modal)) {
                $modal.fadeOut(200, function() {
                    $(this).remove();
                });
            }
        });
        
        // Copy CSS button
        $modal.find('#fontprotect-copy-css').on('click', function() {
            var textarea = $modal.find('textarea')[0];
            
            textarea.select();
            document.execCommand('copy');
            
            $(this).text('Copied!');
            setTimeout(function() {
                $('#fontprotect-copy-css').text('Copy to Clipboard');
            }, 2000);
        });
    }
})(jQuery);