<?php
/*
 * Plugin Name:       Font Protection for Media Offloader
 * Description:       Robust solution that restores font files that have been offloaded to cloud storage.
 * Version:           2.0.0
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            YP Studio
 * Author URI:        https://www.yp.studio
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       font-protection
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
    }

// Define plugin constants
define('FONTPROTECT_VERSION', '2.0.0');
define('FONTPROTECT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FONTPROTECT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FONTPROTECT_ASSETS_URL', FONTPROTECT_PLUGIN_URL . 'assets/');

class Font_Protection_Plugin {
    // Define font extensions to protect
    private $font_extensions = ['ttf', 'woff', 'woff2', 'eot', 'otf', 'svg'];
    
    // Logging levels
    private $log_levels = [
        'info' => 'Information',
        'warning' => 'Warning',
        'error' => 'Error',
        'success' => 'Success'
    ];
    
    // Debug mode - can be enabled in settings
    private $debug_mode = false;
    
    // Max logs to keep
    private $max_logs = 100;
    
    // Cache of processed attachment IDs
    private $processed_attachments = [];
    
    // Constructor
    public function __construct() {
        // Load settings
        $this->load_settings();
        
        // Register hooks
        add_action('init', [$this, 'init']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_menu', [$this, 'add_menu_page']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        
        // Register custom interval for cron
        add_filter('cron_schedules', [$this, 'add_cron_interval']);
        
        // Register cron actions
        add_action('fontprotect_restore_fonts', [$this, 'restore_fonts']);
        add_action('fontprotect_cleanup_logs', [$this, 'cleanup_logs']);
        
        // Register activation/deactivation hooks
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        
        // Fix URLs - Increase priority to ensure our filter runs last
        add_filter('wp_get_attachment_url', [$this, 'fix_font_url'], 9999, 2);
        add_filter('wp_get_attachment_image_src', [$this, 'intercept_get_attachment_image_src'], 9999, 4);
        
        // Direct fix for page builder fonts
        add_action('elementor_pro/custom_fonts/font_uploaded', [$this, 'handle_elementor_font'], 10, 3);
        add_action('bricks_after_custom_font_save', [$this, 'handle_bricks_font'], 10, 2);
        add_filter('elementor/font/font_face_src_url', [$this, 'fix_elementor_font_face_url'], 10, 2);
        add_filter('bricks/font/font_face_src_url', [$this, 'fix_bricks_font_face_url'], 10, 2);
        
        // Add shutdown checks
        add_action('shutdown', [$this, 'shutdown_check']);
        
        // Add filters to override the cached URLs
        add_filter('clean_url', [$this, 'clean_font_url'], 9999, 3);
        
        // Add special AJAX endpoints
        add_action('wp_ajax_fontprotect_check', [$this, 'ajax_font_check']);
        add_action('wp_ajax_nopriv_fontprotect_check', [$this, 'ajax_font_check']);
        add_action('wp_ajax_fontprotect_force_restore', [$this, 'ajax_force_restore']);
        add_action('wp_ajax_fontprotect_clear_cache', [$this, 'ajax_clear_cache']);
        add_action('wp_ajax_fontprotect_export_logs', [$this, 'ajax_export_logs']);
        
        // Add first access interception
        add_action('wp', [$this, 'intercept_first_access']);
        
        // Add rapid check scheduling for uploads
        add_action('add_attachment', [$this, 'schedule_rapid_checks']);
        add_action('wp_update_attachment_metadata', [$this, 'schedule_rapid_checks']);
        
        // Prevent font files from being reoffloaded
        add_filter('advmo_should_offload_attachment', [$this, 'prevent_font_reoffload'], 9999, 2);
        
        // Add CSS fix in head
        add_action('wp_head', [$this, 'add_font_css_fix'], 999);
    }
    
    /**
     * Load plugin settings
     */
    public function load_settings() {
        $settings = get_option('fontprotect_settings', []);
        
        // Set default settings if not set
        if (empty($settings)) {
            $settings = [
                'debug_mode' => false,
                'auto_restore' => true,
                'scan_interval' => 15,
                'max_logs' => 100,
                'css_fix' => true,
                'notification_email' => get_option('admin_email')
            ];
            update_option('fontprotect_settings', $settings);
        }
        
        // Apply settings
        $this->debug_mode = isset($settings['debug_mode']) ? (bool)$settings['debug_mode'] : false;
        $this->max_logs = isset($settings['max_logs']) ? intval($settings['max_logs']) : 100;
    }
    
    /**
     * Initialize the plugin
     */
    public function init() {
        // Load text domain for translations
        load_plugin_textdomain('font-protection', false, dirname(plugin_basename(__FILE__)) . '/languages');
        
        // Ensure our cron jobs are scheduled
        $this->setup_cron_jobs();
        
        // Create necessary directories
        $this->create_plugin_directories();
    }
    
    /**
     * Admin initialization
     */
    public function admin_init() {
        // Register settings
        register_setting('fontprotect_settings', 'fontprotect_settings');
        
        // Add admin notice for offloaded fonts
        $this->add_admin_notice();
        
        // Immediate restoration for recent fonts
        if ($this->get_setting('auto_restore', true)) {
            $this->immediate_restore_recent_fonts();
        }
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Ensure default settings are created
        $this->load_settings();
        
        // Setup initial cron jobs
        $this->setup_cron_jobs();
        
        // Create necessary directories
        $this->create_plugin_directories();
        
        // Log the activation
        $this->log('info', 'Plugin Activated', 'Font Protection plugin activated');
        
        // Run initial font restoration
        $this->schedule_rapid_checks();
    }
    
    /**
     * Create plugin directories
     */
    public function create_plugin_directories() {
        // Create logs directory
        $upload_dir = wp_upload_dir();
        $logs_dir = $upload_dir['basedir'] . '/fontprotect/logs';
        
        if (!file_exists($logs_dir)) {
            wp_mkdir_p($logs_dir);
            
            // Create .htaccess to protect logs
            $htaccess = "# Protect Directory\nDeny from all";
            @file_put_contents($logs_dir . '/.htaccess', $htaccess);
        }
    }
    
    /**
     * Setup cron jobs
     */
    public function setup_cron_jobs() {
        // Font restoration job
        if (!wp_next_scheduled('fontprotect_restore_fonts')) {
            $interval = $this->get_setting('scan_interval', 15);
            wp_schedule_event(time(), "fontprotect_every_{$interval}seconds", 'fontprotect_restore_fonts');
        }
        
        // Log cleanup job - runs daily
        if (!wp_next_scheduled('fontprotect_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'fontprotect_cleanup_logs');
        }
    }
    
    /**
     * Add custom cron interval
     */
    public function add_cron_interval($schedules) {
        $interval = $this->get_setting('scan_interval', 15);
        
        $schedules["fontprotect_every_{$interval}seconds"] = [
            'interval' => $interval,
            'display' => sprintf(__('Every %d seconds', 'font-protection'), $interval)
        ];
        
        return $schedules;
    }
    
    /**
     * Get a specific setting
     */
    public function get_setting($key, $default = null) {
        $settings = get_option('fontprotect_settings', []);
        return isset($settings[$key]) ? $settings[$key] : $default;
    }
    
    /**
     * Enqueue admin assets
     */
    public function enqueue_admin_assets($hook) {
        // Only load on our admin page
        if ($hook != 'tools_page_font-protection') {
            return;
        }
        
        // Enqueue the CSS
        wp_enqueue_style(
            'fontprotect-admin-css',
            plugins_url('assets/css/admin.css', __FILE__),
            [],
            FONTPROTECT_VERSION
        );
        
        // Enqueue the JS
        wp_enqueue_script(
            'fontprotect-admin-js',
            plugins_url('assets/js/admin.js', __FILE__),
            ['jquery'],
            FONTPROTECT_VERSION,
            true
        );
        
        // Add localized script data
        wp_localize_script('fontprotect-admin-js', 'fontProtectData', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('fontprotect-admin'),
            'i18n' => [
                'confirmRestore' => __('Are you sure you want to restore all font files? This may take a moment.', 'font-protection'),
                'confirmClearCache' => __('Are you sure you want to clear the WordPress cache?', 'font-protection'),
                'success' => __('Success!', 'font-protection'),
                'error' => __('Error:', 'font-protection'),
                'loading' => __('Processing...', 'font-protection')
            ]
        ]);
    }
    
    /**
     * Add admin notice
     */
    public function add_admin_notice() {
        // Get font file stats
        $stats = $this->get_font_stats();
        
        if ($stats['offloaded'] > 0) {
            add_action('admin_notices', function() use ($stats) {
                ?>
                <div class="notice notice-warning is-dismissible">
                    <p>
                        <strong><?php _e('Font Protection:', 'font-protection'); ?></strong> 
                        <?php printf(
                            _n(
                                'Found %d offloaded font file that needs restoration.', 
                                'Found %d offloaded font files that need restoration.', 
                                $stats['offloaded'], 
                                'font-protection'
                            ), 
                            $stats['offloaded']
                        ); ?> 
                        <a href="<?php echo admin_url('tools.php?page=font-protection'); ?>"><?php _e('View Details', 'font-protection'); ?></a>
                    </p>
                </div>
                <?php
            });
            
            // If auto-restore is enabled, schedule rapid checks
            if ($this->get_setting('auto_restore', true)) {
                $this->schedule_rapid_checks();
            }
        }
    }
    
    /**
     * Add menu page
     */
    public function add_menu_page() {
        add_submenu_page(
            'tools.php',
            __('Font Protection', 'font-protection'),
            __('Font Protection', 'font-protection'),
            'manage_options',
            'font-protection',
            [$this, 'render_page']
        );
    }
    
    /**
     * Render the admin page
     */
    public function render_page() {
        // Get current stats
        $stats = $this->get_font_stats();
        
        // Check if we need to show a specific tab
        $current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'dashboard';
        
        ?>
        <div class="wrap fontprotect-wrap">
            <h1><?php _e('Font Protection for Media Offloader', 'font-protection'); ?></h1>
            
            <nav class="nav-tab-wrapper">
                <a href="<?php echo admin_url('tools.php?page=font-protection&tab=dashboard'); ?>" class="nav-tab <?php echo $current_tab === 'dashboard' ? 'nav-tab-active' : ''; ?>"><?php _e('Dashboard', 'font-protection'); ?></a>
                <a href="<?php echo admin_url('tools.php?page=font-protection&tab=logs'); ?>" class="nav-tab <?php echo $current_tab === 'logs' ? 'nav-tab-active' : ''; ?>"><?php _e('Activity Logs', 'font-protection'); ?></a>
                <a href="<?php echo admin_url('tools.php?page=font-protection&tab=settings'); ?>" class="nav-tab <?php echo $current_tab === 'settings' ? 'nav-tab-active' : ''; ?>"><?php _e('Settings', 'font-protection'); ?></a>
                <a href="<?php echo admin_url('tools.php?page=font-protection&tab=tools'); ?>" class="nav-tab <?php echo $current_tab === 'tools' ? 'nav-tab-active' : ''; ?>"><?php _e('Tools', 'font-protection'); ?></a>
            </nav>
            
            <div class="fontprotect-content">
                <?php
                // Load the appropriate tab content
                switch ($current_tab) {
                    case 'logs':
                        $this->render_logs_tab();
                        break;
                    case 'settings':
                        $this->render_settings_tab();
                        break;
                    case 'tools':
                        $this->render_tools_tab();
                        break;
                    default:
                        $this->render_dashboard_tab($stats);
                        break;
                }
                ?>
            </div>
        </div>
        <?php
        
        // Handle actions
        if (isset($_GET['action'])) {
            if ($_GET['action'] === 'restore' && wp_verify_nonce($_GET['_wpnonce'] ?? '', 'fontprotect_restore')) {
                $this->restore_fonts(true);
                echo '<script>window.location.href = "' . admin_url('tools.php?page=font-protection&restored=1') . '";</script>';
            } elseif ($_GET['action'] === 'clear_cache' && wp_verify_nonce($_GET['_wpnonce'] ?? '', 'fontprotect_clear_cache')) {
                $this->clear_wordpress_cache();
                echo '<script>window.location.href = "' . admin_url('tools.php?page=font-protection&cache_cleared=1') . '";</script>';
            }
        }
        
        // Show success message
        if (isset($_GET['restored']) && $_GET['restored'] === '1') {
            echo '<div class="notice notice-success is-dismissible"><p>' . __('Font files have been restored successfully!', 'font-protection') . '</p></div>';
        }
        
        if (isset($_GET['cache_cleared']) && $_GET['cache_cleared'] === '1') {
            echo '<div class="notice notice-success is-dismissible"><p>' . __('WordPress cache has been cleared successfully!', 'font-protection') . '</p></div>';
        }
    }
    
    /**
     * Render dashboard tab
     */
    public function render_dashboard_tab($stats) {
        ?>
        <div class="fontprotect-dashboard">
            <div class="fontprotect-stats-grid">
                <div class="fontprotect-stat-card">
                    <div class="fontprotect-stat-icon dashicons dashicons-media-text"></div>
                    <div class="fontprotect-stat-content">
                        <h3><?php _e('Total Font Files', 'font-protection'); ?></h3>
                        <div class="fontprotect-stat-number"><?php echo $stats['total']; ?></div>
                    </div>
                </div>
                
                <div class="fontprotect-stat-card <?php echo $stats['offloaded'] > 0 ? 'fontprotect-warning' : ''; ?>">
                    <div class="fontprotect-stat-icon dashicons dashicons-cloud"></div>
                    <div class="fontprotect-stat-content">
                        <h3><?php _e('Offloaded Fonts', 'font-protection'); ?></h3>
                        <div class="fontprotect-stat-number"><?php echo $stats['offloaded']; ?></div>
                    </div>
                </div>
                
                <div class="fontprotect-stat-card fontprotect-success">
                    <div class="fontprotect-stat-icon dashicons dashicons-shield"></div>
                    <div class="fontprotect-stat-content">
                        <h3><?php _e('Protected Fonts', 'font-protection'); ?></h3>
                        <div class="fontprotect-stat-number"><?php echo $stats['protected']; ?></div>
                    </div>
                </div>
                
                <div class="fontprotect-stat-card">
                    <div class="fontprotect-stat-icon dashicons dashicons-clock"></div>
                    <div class="fontprotect-stat-content">
                        <h3><?php _e('Last Scan', 'font-protection'); ?></h3>
                        <div class="fontprotect-stat-number">
                            <?php 
                            $last_run = get_option('fontprotect_last_run', 0);
                            echo $last_run ? human_time_diff($last_run, time()) . ' ' . __('ago', 'font-protection') : __('Never', 'font-protection'); 
                            ?>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="fontprotect-dashboard-actions">
                <a href="<?php echo wp_nonce_url(admin_url('tools.php?page=font-protection&action=restore'), 'fontprotect_restore'); ?>" class="button button-primary"><?php _e('Restore All Font Files Now', 'font-protection'); ?></a>
                <a href="<?php echo wp_nonce_url(admin_url('tools.php?page=font-protection&action=clear_cache'), 'fontprotect_clear_cache'); ?>" class="button button-secondary"><?php _e('Clear WordPress Cache', 'font-protection'); ?></a>
            </div>
            
            <?php if (!empty($stats['recent_activity'])): ?>
                <div class="fontprotect-card fontprotect-recent-activity">
                    <h2><?php _e('Recent Activity', 'font-protection'); ?></h2>
                    <table class="widefat">
                        <thead>
                            <tr>
                                <th><?php _e('Time', 'font-protection'); ?></th>
                                <th><?php _e('Level', 'font-protection'); ?></th>
                                <th><?php _e('Action', 'font-protection'); ?></th>
                                <th><?php _e('File', 'font-protection'); ?></th>
                                <th><?php _e('Details', 'font-protection'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            $count = 0;
                            foreach ($stats['recent_activity'] as $activity): 
                                if ($count >= 5) break; // Show only 5 recent activities on dashboard
                                $count++;
                            ?>
                                <tr class="fontprotect-log-<?php echo esc_attr($activity['level']); ?>">
                                    <td><?php echo esc_html($activity['time']); ?></td>
                                    <td><span class="fontprotect-log-level fontprotect-log-level-<?php echo esc_attr($activity['level']); ?>"><?php echo esc_html($this->log_levels[$activity['level']] ?? $activity['level']); ?></span></td>
                                    <td><?php echo esc_html($activity['action']); ?></td>
                                    <td><?php echo esc_html($activity['file']); ?></td>
                                    <td>
                                        <?php if (!empty($activity['details'])): ?>
                                            <div class="fontprotect-log-details"><?php echo esc_html($activity['details']); ?></div>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <p class="fontprotect-view-all">
                        <a href="<?php echo admin_url('tools.php?page=font-protection&tab=logs'); ?>"><?php _e('View All Activity Logs', 'font-protection'); ?></a>
                    </p>
                </div>
            <?php endif; ?>
            
            <?php if ($this->debug_mode && isset($stats['debug_info']) && !empty($stats['debug_info'])): ?>
                <div class="fontprotect-card fontprotect-debug-info">
                    <h2><?php _e('Debug Information', 'font-protection'); ?></h2>
                    <div class="fontprotect-debug-table">
                        <?php foreach ($stats['debug_info'] as $file): ?>
                            <div class="fontprotect-debug-file">
                                <h3><?php echo esc_html($file['title']); ?> (ID: <?php echo esc_html($file['id']); ?>)</h3>
                                <table class="widefat striped">
                                    <tbody>
                                        <?php foreach ($file as $key => $value): ?>
                                            <?php if ($key !== 'id' && $key !== 'title'): ?>
                                            <tr>
                                                <th><?php echo esc_html(ucfirst(str_replace('_', ' ', $key))); ?></th>
                                                <td><?php echo esc_html($value); ?></td>
                                            </tr>
                                            <?php endif; ?>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
            
            <div class="fontprotect-card fontprotect-how-it-works">
                <h2><?php _e('How This Plugin Works', 'font-protection'); ?></h2>
                <div class="fontprotect-how-it-works-content">
                    <p><?php _e('This plugin takes a proactive approach to font protection:', 'font-protection'); ?></p>
                    <ol>
                        <li><?php _e('It scans for font files that have been offloaded to cloud storage', 'font-protection'); ?></li>
                        <li><?php _e('When it finds an offloaded font file, it downloads it back to your server', 'font-protection'); ?></li>
                        <li><?php _e('It then modifies the URLs to ensure your site uses the local copy', 'font-protection'); ?></li>
                        <li><?php _e('This process runs automatically at regular intervals', 'font-protection'); ?></li>
                        <li><?php _e('Special hooks for Elementor and Bricks Builder ensure compatibility with these page builders', 'font-protection'); ?></li>
                    </ol>
                    <p><strong><?php _e('Note:', 'font-protection'); ?></strong> <?php _e('This plugin does not prevent the initial offloading. Instead, it actively restores font files after they\'ve been offloaded.', 'font-protection'); ?></p>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Render logs tab
     */
    public function render_logs_tab() {
        // Get activity logs
        $activity_logs = get_option('fontprotect_recent_activity', []);
        
        // Filtering options
        $level_filter = isset($_GET['level']) ? sanitize_text_field($_GET['level']) : '';
        $search_term = isset($_GET['search']) ? sanitize_text_field($_GET['search']) : '';
        
        // Apply filters
        if (!empty($level_filter) || !empty($search_term)) {
            $filtered_logs = [];
            
            foreach ($activity_logs as $log) {
                $level_match = empty($level_filter) || $log['level'] === $level_filter;
                $search_match = empty($search_term) || 
                               (stripos($log['action'], $search_term) !== false || 
                                stripos($log['file'], $search_term) !== false || 
                                stripos($log['details'], $search_term) !== false);
                
                if ($level_match && $search_match) {
                    $filtered_logs[] = $log;
                }
            }
            
            $activity_logs = $filtered_logs;
        }
        
        ?>
        <div class="fontprotect-logs">
            <div class="fontprotect-logs-header">
                <h2><?php _e('Activity Logs', 'font-protection'); ?></h2>
                
                <div class="fontprotect-logs-actions">
                    <form method="get" class="fontprotect-log-filters">
                        <input type="hidden" name="page" value="font-protection">
                        <input type="hidden" name="tab" value="logs">
                        
                        <select name="level">
                            <option value=""><?php _e('All Levels', 'font-protection'); ?></option>
                            <?php foreach ($this->log_levels as $level_key => $level_name): ?>
                                <option value="<?php echo esc_attr($level_key); ?>" <?php selected($level_filter, $level_key); ?>><?php echo esc_html($level_name); ?></option>
                            <?php endforeach; ?>
                        </select>
                        
                        <input type="text" name="search" placeholder="<?php esc_attr_e('Search logs...', 'font-protection'); ?>" value="<?php echo esc_attr($search_term); ?>">
                        
                        <button type="submit" class="button"><?php _e('Filter', 'font-protection'); ?></button>
                        <?php if (!empty($level_filter) || !empty($search_term)): ?>
                            <a href="<?php echo admin_url('tools.php?page=font-protection&tab=logs'); ?>" class="button"><?php _e('Reset', 'font-protection'); ?></a>
                        <?php endif; ?>
                    </form>
                    
                    <div class="fontprotect-log-export">
                        <button id="fontprotect-export-logs" class="button"><?php _e('Export Logs', 'font-protection'); ?></button>
                        <button id="fontprotect-clear-logs" class="button button-link-delete"><?php _e('Clear Logs', 'font-protection'); ?></button>
                    </div>
                </div>
            </div>
            
            <?php if (empty($activity_logs)): ?>
                <div class="fontprotect-notice fontprotect-notice-info">
                    <p><?php _e('No activity logs found.', 'font-protection'); ?></p>
                </div>
            <?php else: ?>
                <table class="widefat fontprotect-logs-table">
                    <thead>
                        <tr>
                            <th><?php _e('Time', 'font-protection'); ?></th>
                            <th><?php _e('Level', 'font-protection'); ?></th>
                            <th><?php _e('Action', 'font-protection'); ?></th>
                            <th><?php _e('File', 'font-protection'); ?></th>
                            <th><?php _e('Details', 'font-protection'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($activity_logs as $activity): ?>
                            <tr class="fontprotect-log-<?php echo esc_attr($activity['level']); ?>">
                                <td><?php echo esc_html($activity['time']); ?></td>
                                <td><span class="fontprotect-log-level fontprotect-log-level-<?php echo esc_attr($activity['level']); ?>"><?php echo esc_html($this->log_levels[$activity['level']] ?? $activity['level']); ?></span></td>
                                <td><?php echo esc_html($activity['action']); ?></td>
                                <td><?php echo esc_html($activity['file']); ?></td>
                                <td>
                                    <?php if (!empty($activity['details'])): ?>
                                        <div class="fontprotect-log-details"><?php echo esc_html($activity['details']); ?></div>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }
    
    /**
     * Render settings tab
     */
    public function render_settings_tab() {
        // Save settings if form submitted
        if (isset($_POST['fontprotect_save_settings']) && check_admin_referer('fontprotect_settings')) {
            $settings = [
                'debug_mode' => isset($_POST['debug_mode']),
                'auto_restore' => isset($_POST['auto_restore']),
                'scan_interval' => absint($_POST['scan_interval']),
                'max_logs' => absint($_POST['max_logs']),
                'css_fix' => isset($_POST['css_fix']),
                'notification_email' => sanitize_email($_POST['notification_email'])
            ];
            
            // Save settings
            update_option('fontprotect_settings', $settings);
            
            // Reload settings
            $this->load_settings();
            
            // Reschedule cron jobs if interval changed
            wp_clear_scheduled_hook('fontprotect_restore_fonts');
            $this->setup_cron_jobs();
            
            // Log the settings update
            $this->log('info', 'Settings Updated', 'Plugin settings were updated');
            
            // Show success message
            echo '<div class="notice notice-success is-dismissible"><p>' . __('Settings saved successfully!', 'font-protection') . '</p></div>';
        }
        
        // Get current settings
        $settings = get_option('fontprotect_settings', []);
        ?>
        <div class="fontprotect-settings">
            <form method="post" action="">
                <?php wp_nonce_field('fontprotect_settings'); ?>
                
                <div class="fontprotect-card">
                    <h2><?php _e('General Settings', 'font-protection'); ?></h2>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php _e('Debug Mode', 'font-protection'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="debug_mode" <?php checked(isset($settings['debug_mode']) ? $settings['debug_mode'] : false); ?>>
                                    <?php _e('Enable debug mode', 'font-protection'); ?>
                                </label>
                                <p class="description"><?php _e('When enabled, additional debug information will be displayed in the dashboard.', 'font-protection'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Auto Restore', 'font-protection'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="auto_restore" <?php checked(isset($settings['auto_restore']) ? $settings['auto_restore'] : true); ?>>
                                    <?php _e('Automatically restore offloaded font files', 'font-protection'); ?>
                                </label>
                                <p class="description"><?php _e('When enabled, the plugin will automatically restore offloaded font files.', 'font-protection'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Scan Interval', 'font-protection'); ?></th>
                            <td>
                                <select name="scan_interval">
                                    <option value="15" <?php selected(isset($settings['scan_interval']) ? $settings['scan_interval'] : 15, 15); ?>><?php _e('Every 15 seconds', 'font-protection'); ?></option>
                                    <option value="30" <?php selected(isset($settings['scan_interval']) ? $settings['scan_interval'] : 15, 30); ?>><?php _e('Every 30 seconds', 'font-protection'); ?></option>
                                    <option value="60" <?php selected(isset($settings['scan_interval']) ? $settings['scan_interval'] : 15, 60); ?>><?php _e('Every minute', 'font-protection'); ?></option>
                                    <option value="300" <?php selected(isset($settings['scan_interval']) ? $settings['scan_interval'] : 15, 300); ?>><?php _e('Every 5 minutes', 'font-protection'); ?></option>
                                </select>
                                <p class="description"><?php _e('How often the plugin should scan for offloaded font files.', 'font-protection'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Maximum Logs', 'font-protection'); ?></th>
                            <td>
                                <input type="number" name="max_logs" min="10" max="1000" value="<?php echo isset($settings['max_logs']) ? intval($settings['max_logs']) : 100; ?>">
                                <p class="description"><?php _e('Maximum number of log entries to keep.', 'font-protection'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('CSS Fix', 'font-protection'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="css_fix" <?php checked(isset($settings['css_fix']) ? $settings['css_fix'] : true); ?>>
                                    <?php _e('Add CSS fixes for font URLs', 'font-protection'); ?>
                                </label>
                                <p class="description"><?php _e('When enabled, the plugin will add CSS fixes to ensure font URLs are correctly resolved.', 'font-protection'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Notification Email', 'font-protection'); ?></th>
                            <td>
                                <input type="email" name="notification_email" value="<?php echo isset($settings['notification_email']) ? esc_attr($settings['notification_email']) : get_option('admin_email'); ?>">
                                <p class="description"><?php _e('Email address for important notifications.', 'font-protection'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <div class="fontprotect-card">
                    <h2><?php _e('Page Builder Integration', 'font-protection'); ?></h2>
                    
                    <div class="fontprotect-builder-info">
                        <div class="fontprotect-builder">
                            <img src="<?php echo plugins_url('assets/images/elementor-logo.png', __FILE__); ?>" alt="Elementor">
                            <h3><?php _e('Elementor Support', 'font-protection'); ?></h3>
                            <p><?php _e('Special handling for Elementor\'s font loading mechanism.', 'font-protection'); ?></p>
                            <p class="fontprotect-status fontprotect-status-active"><?php _e('Active', 'font-protection'); ?></p>
                        </div>
                        
                        <div class="fontprotect-builder">
                            <img src="<?php echo plugins_url('assets/images/bricks-logo.png', __FILE__); ?>" alt="Bricks">
                            <h3><?php _e('Bricks Builder Support', 'font-protection'); ?></h3>
                            <p><?php _e('Special handling for Bricks Builder\'s font loading mechanism.', 'font-protection'); ?></p>
                            <p class="fontprotect-status fontprotect-status-active"><?php _e('Active', 'font-protection'); ?></p>
                        </div>
                    </div>
                </div>
                
                <div class="fontprotect-card">
                    <h2><?php _e('Supported Font Formats', 'font-protection'); ?></h2>
                    
                    <div class="fontprotect-format-grid">
                        <?php foreach ($this->font_extensions as $ext): ?>
                            <div class="fontprotect-format">
                                <div class="fontprotect-format-icon">.<?php echo strtoupper($ext); ?></div>
                                <div class="fontprotect-format-name">
                                    <?php 
                                    switch ($ext) {
                                        case 'ttf':
                                            echo 'TrueType Font';
                                            break;
                                        case 'woff':
                                            echo 'Web Open Font Format';
                                            break;
                                        case 'woff2':
                                            echo 'Web Open Font Format 2';
                                            break;
                                        case 'eot':
                                            echo 'Embedded OpenType';
                                            break;
                                        case 'otf':
                                            echo 'OpenType Font';
                                            break;
                                        case 'svg':
                                            echo 'SVG Font';
                                            break;
                                        default:
                                            echo ucfirst($ext) . ' Font';
                                    }
                                    ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <p class="submit">
                    <input type="submit" name="fontprotect_save_settings" class="button button-primary" value="<?php _e('Save Settings', 'font-protection'); ?>">
                </p>
            </form>
        </div>
        <?php
    }
    
    /**
     * Render tools tab
     */
    public function render_tools_tab() {
        ?>
        <div class="fontprotect-tools">
            <div class="fontprotect-card">
                <h2><?php _e('Font Protection Tools', 'font-protection'); ?></h2>
                
                <div class="fontprotect-tools-grid">
                    <div class="fontprotect-tool">
                        <div class="fontprotect-tool-icon dashicons dashicons-update"></div>
                        <h3><?php _e('Restore All Font Files', 'font-protection'); ?></h3>
                        <p><?php _e('Scan for offloaded font files and restore them to your server.', 'font-protection'); ?></p>
                        <a href="<?php echo wp_nonce_url(admin_url('tools.php?page=font-protection&action=restore'), 'fontprotect_restore'); ?>" class="button button-primary"><?php _e('Run Now', 'font-protection'); ?></a>
                    </div>
                    
                    <div class="fontprotect-tool">
                        <div class="fontprotect-tool-icon dashicons dashicons-trash"></div>
                        <h3><?php _e('Clear WordPress Cache', 'font-protection'); ?></h3>
                        <p><?php _e('Clear all WordPress caches including object cache and popular caching plugins.', 'font-protection'); ?></p>
                        <a href="<?php echo wp_nonce_url(admin_url('tools.php?page=font-protection&action=clear_cache'), 'fontprotect_clear_cache'); ?>" class="button button-secondary"><?php _e('Clear Cache', 'font-protection'); ?></a>
                    </div>
                    
                    <div class="fontprotect-tool">
                        <div class="fontprotect-tool-icon dashicons dashicons-search"></div>
                        <h3><?php _e('Scan Theme for Font References', 'font-protection'); ?></h3>
                        <p><?php _e('Scan your active theme for font references that might need protection.', 'font-protection'); ?></p>
                        <button id="fontprotect-scan-theme" class="button button-secondary"><?php _e('Scan Theme', 'font-protection'); ?></button>
                    </div>
                    
                    <div class="fontprotect-tool">
                        <div class="fontprotect-tool-icon dashicons dashicons-editor-code"></div>
                        <h3><?php _e('Generate Font CSS Fix', 'font-protection'); ?></h3>
                        <p><?php _e('Generate CSS overrides for font files to ensure they are loaded from your server.', 'font-protection'); ?></p>
                        <button id="fontprotect-generate-css" class="button button-secondary"><?php _e('Generate CSS', 'font-protection'); ?></button>
                    </div>
                </div>
            </div>
            
            <div class="fontprotect-card">
                <h2><?php _e('Troubleshooting', 'font-protection'); ?></h2>
                
                <div class="fontprotect-troubleshooting">
                    <div class="fontprotect-troubleshooting-item">
                        <h3><?php _e('Still seeing offloaded fonts?', 'font-protection'); ?></h3>
                        <p><?php _e('If you\'re still seeing fonts loaded from cloud storage, try these steps:', 'font-protection'); ?></p>
                        <ol>
                            <li><?php _e('Clear your browser cache completely', 'font-protection'); ?></li>
                            <li><?php _e('Clear any caching plugins you have installed', 'font-protection'); ?></li>
                            <li><?php _e('Run the "Restore All Font Files" tool above', 'font-protection'); ?></li>
                            <li><?php _e('If using a CDN, purge its cache as well', 'font-protection'); ?></li>
                        </ol>
                    </div>
                    
                    <div class="fontprotect-troubleshooting-item">
                        <h3><?php _e('Font issues with Elementor or Bricks?', 'font-protection'); ?></h3>
                        <p><?php _e('If you\'re experiencing font issues with page builders:', 'font-protection'); ?></p>
                        <ol>
                            <li><?php _e('Clear your page builder\'s cache', 'font-protection'); ?></li>
                            <li><?php _e('Regenerate CSS files in your page builder', 'font-protection'); ?></li>
                            <li><?php _e('Make sure the CSS Fix option is enabled in settings', 'font-protection'); ?></li>
                        </ol>
                    </div>
                </div>
            </div>
            
            <div class="fontprotect-card fontprotect-system-info">
                <h2><?php _e('System Information', 'font-protection'); ?></h2>
                <textarea readonly rows="10" id="fontprotect-system-info"><?php echo esc_textarea($this->get_system_info()); ?></textarea>
                <button class="button button-secondary" id="fontprotect-copy-system-info"><?php _e('Copy to Clipboard', 'font-protection'); ?></button>
            </div>
        </div>
        <?php
    }
    
    /**
     * Generate system information for debugging
     */
    public function get_system_info() {
        global $wpdb;
        
        // WordPress environment
        $wp_info = [
            'WordPress Version:' => get_bloginfo('version'),
            'Site URL:' => get_bloginfo('url'),
            'WordPress URL:' => get_bloginfo('wpurl'),
            'WP Multisite:' => is_multisite() ? 'Yes' : 'No',
            'WordPress Memory Limit:' => WP_MEMORY_LIMIT,
            'WordPress Debug Mode:' => defined('WP_DEBUG') && WP_DEBUG ? 'Yes' : 'No',
            'WordPress Debug Log:' => defined('WP_DEBUG_LOG') && WP_DEBUG_LOG ? 'Yes' : 'No',
            'WordPress Script Debug:' => defined('SCRIPT_DEBUG') && SCRIPT_DEBUG ? 'Yes' : 'No',
            'Current Theme:' => wp_get_theme()->get('Name') . ' ' . wp_get_theme()->get('Version')
        ];
        
        // Plugin info
        $plugin_info = [
            'Plugin Version:' => FONTPROTECT_VERSION,
            'Debug Mode:' => $this->debug_mode ? 'Enabled' : 'Disabled',
            'Auto Restore:' => $this->get_setting('auto_restore', true) ? 'Enabled' : 'Disabled',
            'Scan Interval:' => $this->get_setting('scan_interval', 15) . ' seconds',
            'CSS Fix:' => $this->get_setting('css_fix', true) ? 'Enabled' : 'Disabled',
            'Last Run:' => get_option('fontprotect_last_run', 0) ? date('Y-m-d H:i:s', get_option('fontprotect_last_run')) : 'Never'
        ];
        
        // Font stats
        $stats = $this->get_font_stats();
        
        $font_stats = [
            'Total Font Files:' => $stats['total'],
            'Offloaded Fonts:' => $stats['offloaded'],
            'Protected Fonts:' => $stats['protected']
        ];
        
        // Server environment
        $server_info = [
            'PHP Version:' => PHP_VERSION,
            'MySQL Version:' => $wpdb->db_version(),
            'Web Server:' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'PHP Max Execution Time:' => ini_get('max_execution_time') . ' seconds',
            'PHP Max Input Vars:' => ini_get('max_input_vars'),
            'PHP Post Max Size:' => ini_get('post_max_size'),
            'PHP Max Upload Size:' => ini_get('upload_max_filesize'),
            'PHP Memory Limit:' => ini_get('memory_limit')
        ];
        
        // Active plugins
        $active_plugins = [];
        $all_plugins = get_plugins();
        
        foreach ($all_plugins as $plugin_path => $plugin) {
            if (is_plugin_active($plugin_path)) {
                $active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'];
            }
        }
        
        // Build system info string
        $info = "### FontProtect System Info ###\n\n";
        
        $info .= "## WordPress Environment ##\n";
        foreach ($wp_info as $key => $value) {
            $info .= $key . ' ' . $value . "\n";
        }
        
        $info .= "\n## Plugin Information ##\n";
        foreach ($plugin_info as $key => $value) {
            $info .= $key . ' ' . $value . "\n";
        }
        
        $info .= "\n## Font Statistics ##\n";
        foreach ($font_stats as $key => $value) {
            $info .= $key . ' ' . $value . "\n";
        }
        
        $info .= "\n## Server Environment ##\n";
        foreach ($server_info as $key => $value) {
            $info .= $key . ' ' . $value . "\n";
        }
        
        $info .= "\n## Active Plugins (" . count($active_plugins) . ") ##\n";
        foreach ($active_plugins as $plugin) {
            $info .= $plugin . "\n";
        }
        
        $info .= "\n### End System Info ###";
        
        return $info;
    }
    
    /**
     * Clear WordPress cache
     */
    public function clear_wordpress_cache() {
        global $wp_object_cache;
        
        // Clear object cache
        if (is_object($wp_object_cache) && method_exists($wp_object_cache, 'flush')) {
            $wp_object_cache->flush();
        }
        
        // Clear rewrite rules
        flush_rewrite_rules();
        
        // Try to clear third-party caches
        if (function_exists('wp_cache_clean_cache')) {
            wp_cache_clean_cache('supercache'); // WP Super Cache
        }
        
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all(); // W3 Total Cache
        }
        
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain(); // WP Rocket
        }
        
        if (function_exists('wpfc_clear_all_cache')) {
            wpfc_clear_all_cache(); // WP Fastest Cache
        }
        
        // Delete attachment URL transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '%advmo_url_%'");
        
        // Clear Elementor cache if present
        if (class_exists('\Elementor\Plugin')) {
            \Elementor\Plugin::instance()->files_manager->clear_cache();
        }
        
        // Clear Bricks cache if present
        if (class_exists('\Bricks\Helpers')) {
            \Bricks\Helpers::delete_cached_css_files();
        }
        
        // Log the cache cleared event
        $this->log('success', 'Cache Cleared', 'WordPress', 'Cleared all WordPress caches');
        
        return true;
    }
    
    /**
     * Get font file statistics
     */
    public function get_font_stats() {
        global $wpdb;
        
        $extensions_list = "'" . implode("','", $this->font_extensions) . "'";
        
        // Get total count
        $total_query = "
            SELECT COUNT(p.ID)
            FROM {$wpdb->posts} p
            WHERE p.post_type = 'attachment'
            AND (
                LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
            )
        ";
        
        $total = (int)$wpdb->get_var($total_query);
        
        // Get offloaded count
        $offloaded_query = "
            SELECT COUNT(p.ID)
            FROM {$wpdb->posts} p
            JOIN {$wpdb->postmeta} pm_offloaded ON p.ID = pm_offloaded.post_id AND pm_offloaded.meta_key = 'advmo_offloaded' AND pm_offloaded.meta_value = '1'
            LEFT JOIN {$wpdb->postmeta} pm_provider ON p.ID = pm_provider.post_id AND pm_provider.meta_key = 'advmo_provider'
            WHERE p.post_type = 'attachment'
            AND (
                LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
            )
            AND (
                pm_provider.meta_value != 'fontprotect_local'
                OR pm_provider.meta_value IS NULL
            )
        ";
        
        $offloaded = (int)$wpdb->get_var($offloaded_query);
        
        // Get protected count
        $protected_query = "
            SELECT COUNT(p.ID)
            FROM {$wpdb->posts} p
            JOIN {$wpdb->postmeta} pm_provider ON p.ID = pm_provider.post_id AND pm_provider.meta_key = 'advmo_provider' AND pm_provider.meta_value = 'fontprotect_local'
            WHERE p.post_type = 'attachment'
            AND (
                LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
            )
        ";
        
        $protected = (int)$wpdb->get_var($protected_query);
        
        // Get recent activity
        $activity = get_option('fontprotect_recent_activity', []);
        
        // Get debug info if enabled
        $debug_info = [];
        
        if ($this->debug_mode) {
            $debug_query = "
                SELECT p.ID, p.post_title, p.guid, 
                       pm_offloaded.meta_value as is_offloaded,
                       pm_provider.meta_value as provider,
                       pm_bucket.meta_value as bucket,
                       pm_path.meta_value as path,
                       pm_protected.meta_value as protected_time
                FROM {$wpdb->posts} p
                LEFT JOIN {$wpdb->postmeta} pm_offloaded ON p.ID = pm_offloaded.post_id AND pm_offloaded.meta_key = 'advmo_offloaded'
                LEFT JOIN {$wpdb->postmeta} pm_provider ON p.ID = pm_provider.post_id AND pm_provider.meta_key = 'advmo_provider'
                LEFT JOIN {$wpdb->postmeta} pm_bucket ON p.ID = pm_bucket.post_id AND pm_bucket.meta_key = 'advmo_bucket'
                LEFT JOIN {$wpdb->postmeta} pm_path ON p.ID = pm_path.post_id AND pm_path.meta_key = 'advmo_path'
                LEFT JOIN {$wpdb->postmeta} pm_protected ON p.ID = pm_protected.post_id AND pm_protected.meta_key = 'fontprotect_protected'
                WHERE p.post_type = 'attachment'
                AND (
                    LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
                )
                ORDER BY p.ID DESC
                LIMIT 5
            ";
            
            $debug_files = $wpdb->get_results($debug_query);
            
            foreach ($debug_files as $file) {
                $local_path = get_attached_file($file->ID);
                $file_exists = file_exists($local_path);
                $cloud_url = $this->get_cloud_url_debug($file);
                $current_url = wp_get_attachment_url($file->ID);
                $fixed_url = $this->fix_font_url($current_url, $file->ID);
                
                $debug_info[] = [
                    'id' => $file->ID,
                    'title' => $file->post_title,
                    'guid' => $file->guid,
                    'is_offloaded' => $file->is_offloaded ? 'Yes' : 'No',
                    'provider' => $file->provider ? $file->provider : 'None',
                    'bucket' => $file->bucket ? $file->bucket : 'None',
                    'path' => $file->path ? $file->path : 'None',
                    'protected_time' => $file->protected_time ? date('Y-m-d H:i:s', $file->protected_time) : 'Not protected',
                    'local_path' => $local_path,
                    'file_exists' => $file_exists ? 'Yes' : 'No',
                    'current_url' => $current_url,
                    'fixed_url' => $fixed_url,
                    'cloud_url' => $cloud_url
                ];
            }
        }
        
        return [
            'total' => $total,
            'offloaded' => $offloaded,
            'protected' => $protected,
            'recent_activity' => $activity,
            'debug_info' => $debug_info
        ];
    }
    
    /**
     * Get cloud URL with debug info
     */
    public function get_cloud_url_debug($font_file) {
        // Extract filename from guid
        $filename = basename($font_file->guid);
        
        // Default domain
        $domain = '';
        
        // Construct the cloud URL based on the provider
        switch ($font_file->provider) {
            case 's3':
                $domain = "https://{$font_file->bucket}.s3.amazonaws.com";
                break;
            case 'cloudflare':
            case 'r2':
                $domain = "https://{$font_file->bucket}.r2.cloudflarestorage.com";
                break;
            case 'digitalocean':
            case 'spaces':
                $domain = "https://{$font_file->bucket}.digitaloceanspaces.com";
                break;
            case 'wasabi':
                $domain = "https://s3.wasabisys.com/{$font_file->bucket}";
                break;
            case 'backblaze':
                $domain = "https://f002.backblazeb2.com/file/{$font_file->bucket}";
                break;
            case 'gcp':
            case 'gcs':
                $domain = "https://storage.googleapis.com/{$font_file->bucket}";
                break;
            case 'do':
                $domain = "https://{$font_file->bucket}.digitaloceanspaces.com";
                break;
            case 'minio':
                // Minio can be configured with custom endpoints, try to get the endpoint from metadata
                $endpoint = get_post_meta($font_file->ID, 'advmo_endpoint', true);
                if (!empty($endpoint)) {
                    $domain = rtrim($endpoint, '/');
                } else {
                    $domain = "https://{$font_file->bucket}.minio.example.com"; // Generic fallback
                }
                break;
            case 'custom':
                // Try to get the domain from the current URL
                $current_url = wp_get_attachment_url($font_file->ID);
                $domain = preg_replace('/\/' . preg_quote($filename, '/') . '$/', '', $current_url);
                break;
            case 'custom_domain':
                // Some installations use custom domain mapping
                $custom_domain = get_post_meta($font_file->ID, 'advmo_custom_domain', true);
                if (!empty($custom_domain)) {
                    $domain = rtrim($custom_domain, '/');
                }
                break;
            default:
                // Try to extract from guid if provider not recognized
                if (strpos($font_file->guid, 'http') === 0) {
                    $domain = preg_replace('/\/' . preg_quote($filename, '/') . '$/', '', $font_file->guid);
                }
                break;
        }
        
        // Construct the full URL
        $path = isset($font_file->path) && !empty($font_file->path) ? trim($font_file->path, '/') . '/' : '';
        $url = "{$domain}/{$path}{$filename}";
        
        return $url;
    }
    
    /**
     * Restore font files
     */
    public function restore_fonts($force = false) {
        global $wpdb;
        
        // Check if we've run recently
        $last_run = get_option('fontprotect_last_run', 0);
        $now = time();
        
        if (!$force && ($now - $last_run < $this->get_setting('scan_interval', 15) - 2)) {
            // Don't run too frequently
            return;
        }
        
        // Update last run time
        update_option('fontprotect_last_run', $now);
        
        // Get list of font extensions
        $extensions_list = "'" . implode("','", $this->font_extensions) . "'";
        
        // Determine the batch size
        $batch_size = $force ? 50 : 10;
        
        // Find offloaded font files
        $query = "
            SELECT p.ID, p.post_title, p.guid, pm_provider.meta_value as provider, pm_bucket.meta_value as bucket, pm_path.meta_value as path
            FROM {$wpdb->posts} p
            JOIN {$wpdb->postmeta} pm_offloaded ON p.ID = pm_offloaded.post_id AND pm_offloaded.meta_key = 'advmo_offloaded' AND pm_offloaded.meta_value = '1'
            LEFT JOIN {$wpdb->postmeta} pm_provider ON p.ID = pm_provider.post_id AND pm_provider.meta_key = 'advmo_provider'
            LEFT JOIN {$wpdb->postmeta} pm_bucket ON p.ID = pm_bucket.post_id AND pm_bucket.meta_key = 'advmo_bucket'
            LEFT JOIN {$wpdb->postmeta} pm_path ON p.ID = pm_path.post_id AND pm_path.meta_key = 'advmo_path'
            WHERE p.post_type = 'attachment'
            AND (
                LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
            )
            AND (
                pm_provider.meta_value != 'fontprotect_local' OR
                pm_provider.meta_value IS NULL
            )
            ORDER BY p.ID DESC
            LIMIT {$batch_size}
        ";
        
        $font_files = $wpdb->get_results($query);
        
        if (empty($font_files)) {
            if ($force) {
                $this->log('info', 'No Offloaded Fonts', 'No offloaded font files found during forced scan');
            }
            return;
        }
        
        $success_count = 0;
        $fail_count = 0;
        
        // Process each font file
        foreach ($font_files as $font_file) {
            // First, check if file exists locally
            $file = get_attached_file($font_file->ID);
            
            if (file_exists($file)) {
                // File exists locally, just update the metadata
                $this->update_font_metadata($font_file->ID);
                
                // Log activity
                $this->log('success', 'Fixed Metadata', $font_file->post_title, "Local file exists at: {$file}");
                
                $success_count++;
            } else {
                // File doesn't exist locally, try to download it
                $result = $this->download_font_file($font_file);
                
                if ($result === true) {
                    // Log success
                    $this->log('success', 'Downloaded', $font_file->post_title, "Successfully downloaded to: {$file}");
                    $success_count++;
                } else {
                    // Log failure with error details
                    $this->log('error', 'Download Failed', $font_file->post_title, $result);
                    $fail_count++;
                    
                    // Try alternative download method
                    $alt_result = $this->alt_download_font_file($font_file);
                    if ($alt_result === true) {
                        $this->log('success', 'Alt Download Success', $font_file->post_title, "Used alternative method to download to: {$file}");
                        $success_count++;
                        $fail_count--; // Decrement failure count since we succeeded
                    } else {
                        $this->log('error', 'Alt Download Failed', $font_file->post_title, $alt_result);
                    }
                }
            }
        }
        
        // Log summary if forced scan
        if ($force && ($success_count > 0 || $fail_count > 0)) {
            $this->log(
                $fail_count > 0 ? 'warning' : 'success',
                'Restore Summary',
                'Font Files',
                sprintf(
                    "Processed %d font files. Success: %d, Failures: %d",
                    count($font_files),
                    $success_count,
                    $fail_count
                )
            );
            
            // Send notification email if there were failures
            if ($fail_count > 0) {
                $this->send_notification_email(
                    'Font Protection: Restoration Issues',
                    sprintf(
                        "Font Protection plugin encountered %d failures during font restoration. Please check the activity logs for details.",
                        $fail_count
                    )
                );
            }
        }
        
        return [
            'processed' => count($font_files),
            'success' => $success_count,
            'failed' => $fail_count
        ];
    }
    
    /**
     * Update font file metadata
     */
    public function update_font_metadata($attachment_id) {
        // Get all original metadata first
        $original_provider = get_post_meta($attachment_id, 'advmo_provider', true);
        $original_bucket = get_post_meta($attachment_id, 'advmo_bucket', true);
        $original_path = get_post_meta($attachment_id, 'advmo_path', true);
        
        // Store the original values for reference if not already stored
        if (!get_post_meta($attachment_id, 'fontprotect_original_provider', true)) {
            update_post_meta($attachment_id, 'fontprotect_original_provider', $original_provider);
        }
        
        if (!get_post_meta($attachment_id, 'fontprotect_original_bucket', true)) {
            update_post_meta($attachment_id, 'fontprotect_original_bucket', $original_bucket);
        }
        
        if (!get_post_meta($attachment_id, 'fontprotect_original_path', true)) {
            update_post_meta($attachment_id, 'fontprotect_original_path', $original_path);
        }
        
        // Update with our values
        update_post_meta($attachment_id, 'advmo_provider', 'fontprotect_local');
        update_post_meta($attachment_id, 'advmo_path', 'fontprotect/');
        update_post_meta($attachment_id, 'fontprotect_protected', time());
        
        // Remove any error logs
        delete_post_meta($attachment_id, 'advmo_error_log');
        
        // Important: Clear any URL caches in transients
        $transient_key = 'advmo_url_' . $attachment_id;
        delete_transient($transient_key);
        
        // Save attachment metadata to trigger URL updates
        $meta = wp_get_attachment_metadata($attachment_id);
        if ($meta) {
            wp_update_attachment_metadata($attachment_id, $meta);
        }
        
        return true;
    }
    
    /**
     * Get cloud URL for a font file
     */
    public function get_cloud_url($font_file) {
        // Extract filename from guid
        $filename = basename($font_file->guid);
        
        // Default domain
        $domain = '';
        
        // Construct the cloud URL based on the provider
        switch ($font_file->provider) {
            case 's3':
                $domain = "https://{$font_file->bucket}.s3.amazonaws.com";
                break;
            case 'cloudflare':
            case 'r2':
                $domain = "https://{$font_file->bucket}.r2.cloudflarestorage.com";
                break;
            case 'digitalocean':
            case 'spaces':
                $domain = "https://{$font_file->bucket}.digitaloceanspaces.com";
                break;
            case 'wasabi':
                $domain = "https://s3.wasabisys.com/{$font_file->bucket}";
                break;
            case 'backblaze':
                $domain = "https://f002.backblazeb2.com/file/{$font_file->bucket}";
                break;
            case 'gcp':
            case 'gcs':
                $domain = "https://storage.googleapis.com/{$font_file->bucket}";
                break;
            case 'do':
                $domain = "https://{$font_file->bucket}.digitaloceanspaces.com";
                break;
            case 'minio':
                // Minio can be configured with custom endpoints, try to get the endpoint from metadata
                $endpoint = get_post_meta($font_file->ID, 'advmo_endpoint', true);
                if (!empty($endpoint)) {
                    $domain = rtrim($endpoint, '/');
                } else {
                    $domain = "https://{$font_file->bucket}.minio.example.com"; // Generic fallback
                }
                break;
            case 'custom':
                // Try to get the domain from the current URL
                $current_url = wp_get_attachment_url($font_file->ID);
                $domain = preg_replace('/\/' . preg_quote($filename, '/') . '$/', '', $current_url);
                break;
            case 'custom_domain':
                // Some installations use custom domain mapping
                $custom_domain = get_post_meta($font_file->ID, 'advmo_custom_domain', true);
                if (!empty($custom_domain)) {
                    $domain = rtrim($custom_domain, '/');
                }
                break;
            default:
                // Try to extract from guid if provider not recognized
                if (strpos($font_file->guid, 'http') === 0) {
                    $domain = preg_replace('/\/' . preg_quote($filename, '/') . '$/', '', $font_file->guid);
                }
                return false;
        }
        
        // Construct the full URL
        $path = isset($font_file->path) && !empty($font_file->path) ? trim($font_file->path, '/') . '/' : '';
        $url = "{$domain}/{$path}{$filename}";
        
        return $url;
    }
    
    /**
     * Download a font file from cloud storage
     */
    public function download_font_file($font_file) {
        // First, check if we have the minimum info needed
        if (empty($font_file->provider)) {
            return "Missing provider information for font: {$font_file->post_title}";
        }
        
        if (empty($font_file->bucket) && $font_file->provider !== 'custom' && $font_file->provider !== 'custom_domain') {
            return "Missing bucket information for font: {$font_file->post_title}";
        }
        
        // Get the cloud URL
        $cloud_url = $this->get_cloud_url($font_file);
        
        if (!$cloud_url) {
            return "Failed to construct cloud URL for font: {$font_file->post_title}";
        }
        
        // Get the local file path
        $file = get_attached_file($font_file->ID);
        
        // Ensure the directory exists
        $dir = dirname($file);
        if (!file_exists($dir)) {
            if (!wp_mkdir_p($dir)) {
                return "Failed to create directory: {$dir}";
            }
        }
        
        // Download the file
        $response = wp_remote_get($cloud_url, [
            'timeout' => 30,
            'sslverify' => false,
            'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
        ]);
        
        if (is_wp_error($response)) {
            return "WP Error: " . $response->get_error_message() . " | URL: {$cloud_url}";
        }
        
        if (wp_remote_retrieve_response_code($response) !== 200) {
            return "HTTP Error: " . wp_remote_retrieve_response_code($response) . " | URL: {$cloud_url}";
        }
        
        // Save the file
        $result = file_put_contents($file, wp_remote_retrieve_body($response));
        
        if ($result === false) {
            return "Failed to write file to: {$file}";
        }
        
        // Update the metadata
        $this->update_font_metadata($font_file->ID);
        
        return true;
    }
    
    /**
     * Alternative download method (using current URL)
     */
    public function alt_download_font_file($font_file) {
        // Try using the current URL as a fallback
        $current_url = wp_get_attachment_url($font_file->ID);
        
        if (empty($current_url)) {
            return "No current URL available for font: {$font_file->post_title}";
        }
        
        // Get the local file path
        $file = get_attached_file($font_file->ID);
        
        // Ensure the directory exists
        $dir = dirname($file);
        if (!file_exists($dir)) {
            if (!wp_mkdir_p($dir)) {
                return "Failed to create directory: {$dir}";
            }
        }
        
        // Download the file
        $response = wp_remote_get($current_url, [
            'timeout' => 30,
            'sslverify' => false,
            'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
        ]);
        
        if (is_wp_error($response)) {
            return "WP Error: " . $response->get_error_message() . " | URL: {$current_url}";
        }
        
        if (wp_remote_retrieve_response_code($response) !== 200) {
            return "HTTP Error: " . wp_remote_retrieve_response_code($response) . " | URL: {$current_url}";
        }
        
        // Save the file
        $result = file_put_contents($file, wp_remote_retrieve_body($response));
        
        if ($result === false) {
            return "Failed to write file to: {$file}";
        }
        
        // Update the metadata
        $this->update_font_metadata($font_file->ID);
        
        return true;
    }
    
    /**
     * Fix font URLs in WordPress
     */
    public function fix_font_url($url, $attachment_id) {
        // Check if we've already processed this attachment
        if (isset($this->processed_attachments[$attachment_id])) {
            return $this->processed_attachments[$attachment_id];
        }
        
        // Check if this is a font file
        $file = get_attached_file($attachment_id);
        if (!$file) {
            return $url;
        }
        
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->font_extensions)) {
            return $url;
        }
        
        // Check if we've protected this file
        $protected = get_post_meta($attachment_id, 'fontprotect_protected', true);
        if (!$protected) {
            return $url;
        }
        
        // Check if the file exists locally
        if (!file_exists($file)) {
            return $url;
        }
        
        // Generate the correct local URL
        $upload_dir = wp_upload_dir();
        $base_url = $upload_dir['baseurl'];
        $file_path = str_replace($upload_dir['basedir'], '', $file);
        $local_url = $base_url . $file_path;
        
        // If URL is already correct, return it
        if ($url === $local_url) {
            return $url;
        }
        
        // Store in our cache
        $this->processed_attachments[$attachment_id] = $local_url;
        
        // Log the URL replacement if in debug mode
        if ($this->debug_mode) {
            $this->log('info', 'URL Replaced', basename($file), "Changed: {$url} to {$local_url}");
        }
        
        return $local_url;
    }
    
    /**
     * Intercept get_attachment_image_src to fix font URLs
     */
    public function intercept_get_attachment_image_src($image, $attachment_id, $size, $icon) {
        if (!is_array($image)) {
            return $image;
        }
        
        // Check if this is a font file
        $file = get_attached_file($attachment_id);
        if (!$file) {
            return $image;
        }
        
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->font_extensions)) {
            return $image;
        }
        
        // Fix the URL in the image array
        if (isset($image[0])) {
            $image[0] = $this->fix_font_url($image[0], $attachment_id);
        }
        
        return $image;
    }
    
    /**
     * Clean URL filter - override font URLs at the last possible moment
     */
    public function clean_font_url($url, $original_url, $context) {
        if ($context !== 'display') {
            return $url;
        }
        
        // Quick check if this is potentially a font file
        $ext = strtolower(pathinfo($url, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->font_extensions)) {
            return $url;
        }
        
        // Find the attachment ID for this URL
        $attachment_id = $this->get_attachment_id_from_url($original_url);
        if (!$attachment_id) {
            return $url;
        }
        
        // Apply our fix_font_url function
        $fixed_url = $this->fix_font_url($url, $attachment_id);
        
        return $fixed_url;
    }
    
    /**
     * Get attachment ID from URL
     */
    public function get_attachment_id_from_url($url) {
        global $wpdb;
        
        // Try to find by guid first
        $attachment = $wpdb->get_col($wpdb->prepare("SELECT ID FROM $wpdb->posts WHERE guid=%s;", $url));
        
        if (!empty($attachment)) {
            return $attachment[0];
        }
        
        // Try to extract the filename from the URL
        $filename = basename($url);
        
        // Search for attachments by filename
        $attachment = $wpdb->get_col($wpdb->prepare("
            SELECT p.ID
            FROM $wpdb->posts p
            WHERE p.post_type = 'attachment'
            AND (p.post_name = %s OR p.guid LIKE %s)
        ", pathinfo($filename, PATHINFO_FILENAME), '%' . $filename));
        
        if (!empty($attachment)) {
            return $attachment[0];
        }
        
        return false;
    }
    
    /**
     * Handle Elementor font upload
     */
    public function handle_elementor_font($font_id, $font_data, $meta) {
        $this->log('info', 'Elementor Font', $font_data['font_face'], "Elementor font uploaded with ID: {$font_id}");
        
        // Schedule immediate restoration
        $this->schedule_rapid_checks();
    }
    
    /**
     * Handle Bricks Builder font save
     */
    public function handle_bricks_font($font_id, $font_data) {
        $this->log('info', 'Bricks Font', $font_data['family'] ?? 'Unknown', "Bricks font saved with ID: {$font_id}");
        
        // Schedule immediate restoration
        $this->schedule_rapid_checks();
    }
    
    /**
     * Fix Elementor font face URLs
     */
    public function fix_elementor_font_face_url($url, $font_data) {
        // Quick check if this is potentially a font file
        $ext = strtolower(pathinfo($url, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->font_extensions)) {
            return $url;
        }
        
        // Find the attachment ID for this URL
        $attachment_id = $this->get_attachment_id_from_url($url);
        if (!$attachment_id) {
            return $url;
        }
        
        // Apply our fix_font_url function
        $fixed_url = $this->fix_font_url($url, $attachment_id);
        
        if ($this->debug_mode && $fixed_url !== $url) {
            $this->log('info', 'Elementor Font Fix', basename($url), "Fixed Elementor font URL: {$url} to {$fixed_url}");
        }
        
        return $fixed_url;
    }
    
    /**
     * Fix Bricks Builder font face URLs
     */
    public function fix_bricks_font_face_url($url, $font_data) {
        // Quick check if this is potentially a font file
        $ext = strtolower(pathinfo($url, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->font_extensions)) {
            return $url;
        }
        
        // Find the attachment ID for this URL
        $attachment_id = $this->get_attachment_id_from_url($url);
        if (!$attachment_id) {
            return $url;
        }
        
        // Apply our fix_font_url function
        $fixed_url = $this->fix_font_url($url, $attachment_id);
        
        if ($this->debug_mode && $fixed_url !== $url) {
            $this->log('info', 'Bricks Font Fix', basename($url), "Fixed Bricks font URL: {$url} to {$fixed_url}");
        }
        
        return $fixed_url;
    }
    
    /**
     * Add CSS fix for font URLs in head
     */
    public function add_font_css_fix() {
        // Skip if CSS fix is disabled
        if (!$this->get_setting('css_fix', true)) {
            return;
        }
        
        global $wpdb;
        
        // Get a list of font files that we've protected
        $extensions_list = "'" . implode("','", $this->font_extensions) . "'";
        
        $query = "
            SELECT p.ID, p.guid, pm_path.meta_value as path, pm_bucket.meta_value as bucket, pm_provider.meta_value as provider
            FROM {$wpdb->posts} p
            JOIN {$wpdb->postmeta} pm_protected ON p.ID = pm_protected.post_id AND pm_protected.meta_key = 'fontprotect_protected'
            JOIN {$wpdb->postmeta} pm_provider ON p.ID = pm_provider.post_id AND pm_provider.meta_key = 'advmo_provider' AND pm_provider.meta_value = 'fontprotect_local'
            LEFT JOIN {$wpdb->postmeta} pm_path ON p.ID = pm_path.post_id AND pm_path.meta_key = 'advmo_path'
            LEFT JOIN {$wpdb->postmeta} pm_bucket ON p.ID = pm_bucket.post_id AND pm_bucket.meta_key = 'advmo_bucket'
            WHERE p.post_type = 'attachment'
            AND LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
            LIMIT 100
        ";
        
        $font_files = $wpdb->get_results($query);
        
        if (empty($font_files)) {
            return;
        }
        
        // Start building CSS
        $css = "<style id='fontprotect-css-fix'>\n/* Font Protection CSS Fix */\n";
        
        // Process each font file
        foreach ($font_files as $font_file) {
            // Get the correct local URL
            $file = get_attached_file($font_file->ID);
            if (!file_exists($file)) {
                continue;
            }
            
            $upload_dir = wp_upload_dir();
            $base_url = $upload_dir['baseurl'];
            $file_path = str_replace($upload_dir['basedir'], '', $file);
            $local_url = $base_url . $file_path;
            
            // Generate potential cloud URLs for this font
            $filename = basename($font_file->guid);
            $potentialUrls = $this->generate_potential_cloud_urls($font_file, $filename);
            
            // Add CSS overrides for each potential URL
            foreach ($potentialUrls as $cloudUrl) {
                $css .= "@font-face { src: url({$local_url}) !important; }\n";
                $css .= "src: url({$cloudUrl}) { src: url({$local_url}) !important; }\n";
                
                // Add URL function override
                $css .= "src: url(\"{$cloudUrl}\") { src: url(\"{$local_url}\") !important; }\n";
                
                // Add format version
                $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                $format = 'truetype';
                
                switch ($ext) {
                    case 'woff':
                        $format = 'woff';
                        break;
                    case 'woff2':
                        $format = 'woff2';
                        break;
                    case 'eot':
                        $format = 'embedded-opentype';
                        break;
                    case 'otf':
                        $format = 'opentype';
                        break;
                    case 'svg':
                        $format = 'svg';
                        break;
                }
                
                $css .= "src: url({$cloudUrl}) format('{$format}') { src: url({$local_url}) format('{$format}') !important; }\n";
                $css .= "src: url(\"{$cloudUrl}\") format(\"{$format}\") { src: url(\"{$local_url}\") format(\"{$format}\") !important; }\n";
            }
        }
        
        $css .= "</style>\n";
        
        echo $css;
    }
    
    /**
     * Generate potential cloud URLs for a font file
     */
    private function generate_potential_cloud_urls($font_file, $filename) {
        $urls = [];
        
        // Original provider
        $original_provider = get_post_meta($font_file->ID, 'fontprotect_original_provider', true);
        $original_bucket = get_post_meta($font_file->ID, 'fontprotect_original_bucket', true);
        $original_path = get_post_meta($font_file->ID, 'fontprotect_original_path', true);
        
        // If we have original values
        if ($original_provider && $original_bucket) {
            $path = !empty($original_path) ? trim($original_path, '/') . '/' : '';
            
            switch ($original_provider) {
                case 's3':
                    $urls[] = "https://{$original_bucket}.s3.amazonaws.com/{$path}{$filename}";
                    break;
                case 'cloudflare':
                case 'r2':
                    $urls[] = "https://{$original_bucket}.r2.cloudflarestorage.com/{$path}{$filename}";
                    break;
                case 'digitalocean':
                case 'spaces':
                    $urls[] = "https://{$original_bucket}.digitaloceanspaces.com/{$path}{$filename}";
                    break;
                case 'wasabi':
                    $urls[] = "https://s3.wasabisys.com/{$original_bucket}/{$path}{$filename}";
                    break;
                case 'backblaze':
                    $urls[] = "https://f002.backblazeb2.com/file/{$original_bucket}/{$path}{$filename}";
                    break;
                case 'gcp':
                case 'gcs':
                    $urls[] = "https://storage.googleapis.com/{$original_bucket}/{$path}{$filename}";
                    break;
            }
        }
        
        // Also add current URL to the list
        $current_url = wp_get_attachment_url($font_file->ID);
        if ($current_url) {
            $urls[] = $current_url;
        }
        
        // Add the guid URL
        if (strpos($font_file->guid, 'http') === 0) {
            $urls[] = $font_file->guid;
        }
        
        return array_unique($urls);
    }
    
    /**
     * Check for font files during shutdown
     */
    public function shutdown_check() {
        // Only run during admin or AJAX
        if (!is_admin() && !wp_doing_ajax()) {
            return;
        }
        
        // Check if we've processed media
        if (did_action('add_attachment') || did_action('wp_update_attachment_metadata')) {
            $this->restore_fonts();
        }
    }
    
    /**
     * Log activity
     */
    public function log($level, $action, $file, $details = '') {
        $recent_activity = get_option('fontprotect_recent_activity', []);
        
        // Validate level
        if (!isset($this->log_levels[$level])) {
            $level = 'info';
        }
        
        // Add new activity
        array_unshift($recent_activity, [
            'time' => current_time('mysql'),
            'level' => $level,
            'action' => $action,
            'file' => $file,
            'details' => $details
        ]);
        
        // Limit to maximum number of logs
        $recent_activity = array_slice($recent_activity, 0, $this->max_logs);
        
        // Save
        update_option('fontprotect_recent_activity', $recent_activity);
        
        // Also append to log file if debug mode is enabled
        if ($this->debug_mode) {
            $this->write_to_log_file($level, $action, $file, $details);
        }
    }
    
    /**
     * Write log to file
     */
    private function write_to_log_file($level, $action, $file, $details) {
        $upload_dir = wp_upload_dir();
        $logs_dir = $upload_dir['basedir'] . '/fontprotect/logs';
        
        // Create logs directory if it doesn't exist
        if (!file_exists($logs_dir)) {
            wp_mkdir_p($logs_dir);
            
            // Create .htaccess to protect logs
            $htaccess = "# Protect Directory\nDeny from all";
            @file_put_contents($logs_dir . '/.htaccess', $htaccess);
        }
        
        // Create log file name based on date
        $log_file = $logs_dir . '/fontprotect-' . date('Y-m-d') . '.log';
        
        // Format the log entry
        $log_entry = sprintf(
            "[%s] [%s] %s: %s - %s\n",
            date('Y-m-d H:i:s'),
            strtoupper($level),
            $action,
            $file,
            $details
        );
        
        // Append to log file
        @file_put_contents($log_file, $log_entry, FILE_APPEND);
    }
    
    /**
     * Cleanup old logs
     */
    public function cleanup_logs() {
        $upload_dir = wp_upload_dir();
        $logs_dir = $upload_dir['basedir'] . '/fontprotect/logs';
        
        if (!file_exists($logs_dir)) {
            return;
        }
        
        // Get all log files
        $log_files = glob($logs_dir . '/fontprotect-*.log');
        
        if (empty($log_files)) {
            return;
        }
        
        // Sort log files by date (newest first)
        usort($log_files, function($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        
        // Keep only the 7 most recent log files
        $keep_count = 7;
        
        if (count($log_files) > $keep_count) {
            // Delete older log files
            for ($i = $keep_count; $i < count($log_files); $i++) {
                @unlink($log_files[$i]);
            }
            
            $this->log('info', 'Log Cleanup', 'System', sprintf('Deleted %d old log files', count($log_files) - $keep_count));
        }
    }
    
    /**
     * Send notification email
     */
    public function send_notification_email($subject, $message) {
        $notification_email = $this->get_setting('notification_email', get_option('admin_email'));
        
        if (empty($notification_email)) {
            return false;
        }
        
        $site_name = get_bloginfo('name');
        $site_url = get_bloginfo('url');
        
        $headers = [
            'From: ' . $site_name . ' <' . get_option('admin_email') . '>',
            'Content-Type: text/html; charset=UTF-8'
        ];
        
        $email_template = '
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
            <title>' . esc_html($subject) . '</title>
        </head>
        <body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #dddddd;">
                <tr>
                    <td style="padding: 20px; background-color: #0073aa; color: #ffffff; font-size: 18px; font-weight: bold;">
                        ' . esc_html($subject) . '
                    </td>
                </tr>
                <tr>
                    <td style="padding: 20px;">
                        ' . wpautop(esc_html($message)) . '
                        <p style="margin-top: 20px;">
                            <a href="' . esc_url(admin_url('tools.php?page=font-protection')) . '" style="background-color: #0073aa; color: #ffffff; padding: 10px 15px; text-decoration: none; border-radius: 3px;">View Font Protection</a>
                        </p>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px 20px; background-color: #f8f8f8; color: #666666; font-size: 12px; text-align: center; border-top: 1px solid #dddddd;">
                        This email was sent from ' . esc_html($site_name) . ' (' . esc_url($site_url) . ')
                    </td>
                </tr>
            </table>
        </body>
        </html>
        ';
        
        return wp_mail($notification_email, $subject, $email_template, $headers);
    }
    
    /**
     * AJAX font check handler
     */
    public function ajax_font_check() {
        // Run the restore function in the background
        $this->restore_fonts(true);
        
        wp_send_json_success([
            'status' => 'success',
            'message' => __('Font check completed successfully.', 'font-protection')
        ]);
    }
    
    /**
     * AJAX force restore handler
     */
    public function ajax_force_restore() {
        // Check nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'fontprotect-admin')) {
            wp_send_json_error([
                'message' => __('Security check failed.', 'font-protection')
            ]);
        }
        
        // Run restore with force flag
        $result = $this->restore_fonts(true);
        
        // Clear cache
        $this->clear_wordpress_cache();
        
        wp_send_json_success([
            'status' => 'success',
            'message' => sprintf(
                __('Font restoration completed. Processed %d files, %d successful, %d failed.', 'font-protection'),
                $result['processed'],
                $result['success'],
                $result['failed']
            ),
            'stats' => $result
        ]);
    }
    
    /**
     * AJAX clear cache handler
     */
    public function ajax_clear_cache() {
        // Check nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'fontprotect-admin')) {
            wp_send_json_error([
                'message' => __('Security check failed.', 'font-protection')
            ]);
        }
        
        // Clear cache
        $this->clear_wordpress_cache();
        
        wp_send_json_success([
            'status' => 'success',
            'message' => __('WordPress cache cleared successfully.', 'font-protection')
        ]);
    }
    
    /**
     * AJAX export logs handler
     */
    public function ajax_export_logs() {
        // Check nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'fontprotect-admin')) {
            wp_send_json_error([
                'message' => __('Security check failed.', 'font-protection')
            ]);
        }
        
        // Get activity logs
        $activity_logs = get_option('fontprotect_recent_activity', []);
        
        if (empty($activity_logs)) {
            wp_send_json_error([
                'message' => __('No logs available to export.', 'font-protection')
            ]);
        }
        
        // Prepare CSV data
        $csv_data = [
            [
                __('Time', 'font-protection'),
                __('Level', 'font-protection'),
                __('Action', 'font-protection'),
                __('File', 'font-protection'),
                __('Details', 'font-protection')
            ]
        ];
        
        foreach ($activity_logs as $log) {
            $csv_data[] = [
                $log['time'],
                $this->log_levels[$log['level']] ?? $log['level'],
                $log['action'],
                $log['file'],
                $log['details']
            ];
        }
        
        // Convert to CSV string
        $csv_string = '';
        foreach ($csv_data as $row) {
            $csv_string .= '"' . implode('","', array_map('esc_attr', $row)) . "\"\n";
        }
        
        // Send the CSV
        wp_send_json_success([
            'status' => 'success',
            'csv' => $csv_string,
            'filename' => 'fontprotect-logs-' . date('Y-m-d') . '.csv'
        ]);
    }
    
    /**
     * Immediate restoration of recently uploaded fonts
     */
    public function immediate_restore_recent_fonts() {
        global $wpdb;
        
        // Find font files uploaded in the last minute
        $extensions_list = "'" . implode("','", $this->font_extensions) . "'";
        $recent_time = time() - 60; // Last minute
        
        $query = $wpdb->prepare("
            SELECT p.ID FROM {$wpdb->posts} p
            JOIN {$wpdb->postmeta} pm_offloaded ON p.ID = pm_offloaded.post_id AND pm_offloaded.meta_key = 'advmo_offloaded' AND pm_offloaded.meta_value = '1'
            WHERE p.post_type = 'attachment'
            AND p.post_date >= %s
            AND LOWER(SUBSTRING_INDEX(p.guid, '.', -1)) IN ({$extensions_list})
        ", date('Y-m-d H:i:s', $recent_time));
        
        $recent_fonts = $wpdb->get_col($query);
        
        if (!empty($recent_fonts)) {
            foreach ($recent_fonts as $attachment_id) {
                // Force immediate restoration and log it
                $font_file = get_post($attachment_id);
                $this->log('info', 'Immediate Restore', $font_file->post_title, 'Forcing immediate restoration for newly uploaded font');
                $this->download_font_file((object)[
                    'ID' => $attachment_id,
                    'post_title' => $font_file->post_title,
                    'guid' => $font_file->guid,
                    'provider' => get_post_meta($attachment_id, 'advmo_provider', true),
                    'bucket' => get_post_meta($attachment_id, 'advmo_bucket', true),
                    'path' => get_post_meta($attachment_id, 'advmo_path', true)
                ]);
            }
            return true;
        }
        return false;
    }
    
    /**
     * Intercept first page access after font offloading
     */
    public function intercept_first_access() {
        if (!is_admin() && !isset($_GET['fontprotect_check'])) {
            // Add inline script to force an AJAX check on first page load
            add_action('wp_footer', function() {
                ?>
                <script>
                (function() {
                    if (sessionStorage.getItem('fontprotect_checked')) return;
                    sessionStorage.setItem('fontprotect_checked', '1');
                    
                    var xhr = new XMLHttpRequest();
                    xhr.open('GET', '<?php echo admin_url('admin-ajax.php?action=fontprotect_check&nonce=' . wp_create_nonce('fontprotect_check')); ?>', true);
                    xhr.send();
                })();
                </script>
                <?php
            }, 999);
        }
    }
    
    /**
     * Schedule rapid checks for font restoration
     */
    public function schedule_rapid_checks() {
        // Schedule checks at 2, 5, 10, and 15 seconds
        wp_schedule_single_event(time() + 2, 'fontprotect_restore_fonts');
        wp_schedule_single_event(time() + 5, 'fontprotect_restore_fonts');
        wp_schedule_single_event(time() + 10, 'fontprotect_restore_fonts');
        wp_schedule_single_event(time() + 15, 'fontprotect_restore_fonts');
        
        $this->log('info', 'Rapid Checks', 'System', 'Scheduled rapid font restoration checks');
    }
    
    /**
     * Prevent font files from being reoffloaded
     */
    public function prevent_font_reoffload($should_offload, $attachment_id) {
        // Check if this is a font file
        $file = get_attached_file($attachment_id);
        if (!$file) {
            return $should_offload;
        }
        
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (in_array($ext, $this->font_extensions)) {
            // If it's a font file, prevent offloading
            if ($this->debug_mode) {
                $this->log('warning', 'Prevented Reoffload', basename($file), 'Blocked attempt to reoffload a font file');
            }
            return false;
        }
        
        return $should_offload;
    }
    
        /**
         * Clean up on deactivation
         */
        public function deactivate() {
            // Remove scheduled events
            wp_clear_scheduled_hook('fontprotect_restore_fonts');
            wp_clear_scheduled_hook('fontprotect_cleanup_logs');
            
            $this->log('info', 'Plugin Deactivated', 'System', 'Font Protection plugin deactivated');
        }
    }
    
    // Initialize the plugin
    new Font_Protection_Plugin();