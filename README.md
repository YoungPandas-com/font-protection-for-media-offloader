=== Font Protection for Media Offloader ===
Contributors: wpfitter
Tags: fonts, media offloader, elementor, bricks builder, aws s3, cloud storage
Requires at least: 5.6
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Robust solution that actively restores font files that have been offloaded to cloud storage, with special support for Elementor and Bricks Builder.

== Description ==

**Font Protection for Media Offloader** is a specialized WordPress plugin designed to solve the common problem of fonts not displaying correctly when using media offloader plugins.

### The Problem
Media offloader plugins that move your files to cloud storage (like AWS S3, DigitalOcean Spaces, Cloudflare R2, etc.) can inadvertently break your site's fonts. When font files are offloaded, they often can't be properly loaded by browsers, resulting in fallback fonts being displayed instead.

### The Solution
This plugin takes a proactive approach:

1. It continuously scans for font files that have been offloaded to cloud storage
2. When it finds an offloaded font file, it downloads it back to your server
3. It then modifies the URLs to ensure your site uses the local copy
4. Special handling for Elementor and Bricks Builder ensures compatibility with these popular page builders

### Key Features

* **Automatic Font Protection:** Continuously monitors and restores offloaded font files
* **Page Builder Support:** Special integration with Elementor and Bricks Builder
* **Real-time Monitoring:** Detects and fixes offloaded fonts within seconds
* **Dashboard Overview:** Clear statistics on protected and offloaded fonts
* **Detailed Logging:** Track all font protection activities
* **CSS Fixes:** Adds CSS overrides to ensure fonts load correctly
* **Multiple Format Support:** Works with TTF, WOFF, WOFF2, EOT, OTF, and SVG fonts
* **Troubleshooting Tools:** Scan theme files, generate CSS fixes, and more

### Perfect For

* Sites using media offloader plugins with cloud storage
* Websites built with Elementor or Bricks Builder
* Anyone experiencing font display issues after offloading media
* Developers looking for a reliable font protection solution

### Note

This plugin does not prevent the initial offloading of font files. Instead, it actively restores them after they've been offloaded, ensuring your site's fonts always display correctly.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/font-protection-for-media-offloader` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to Tools > Font Protection to access the plugin's dashboard.
4. The plugin will automatically begin scanning for and restoring offloaded font files.
5. Review the settings to customize the plugin's behavior according to your needs.

== Frequently Asked Questions ==

= How does this plugin work? =

The plugin continuously scans your media library for font files that have been offloaded to cloud storage. When it finds an offloaded font file, it downloads it back to your server and updates the metadata to ensure that your site uses the local copy instead of the cloud-hosted version.

= Is this compatible with my media offloader plugin? =

Yes, this plugin is designed to work with all major media offloader plugins, including:
* WP Offload Media
* Media Cloud
* Advanced Media Offloader
* WP Media Offload
* And most other S3/cloud storage offloader plugins

= What font formats are supported? =

The plugin supports all common web font formats:
* TTF (TrueType Font)
* WOFF (Web Open Font Format)
* WOFF2 (Web Open Font Format 2)
* EOT (Embedded OpenType)
* OTF (OpenType Font)
* SVG (SVG Font)

= Will this slow down my website? =

No. The plugin operates mostly in the background and is designed to be very lightweight. The only time it actively works is when:
1. It performs its scheduled scan (which uses minimal resources)
2. When it needs to download a font file (which typically happens only once per font)

= Does this work with Elementor and Bricks Builder? =

Yes! The plugin includes special integration for both Elementor and Bricks Builder, ensuring that fonts used in these page builders will display correctly even if they've been offloaded to cloud storage.

= I'm still seeing offloaded fonts. What should I do? =

If you're still experiencing issues:
1. Go to Tools > Font Protection > Tools
2. Click "Restore All Font Files Now"
3. Click "Clear WordPress Cache"
4. Clear your browser cache
5. If using a CDN, purge your CDN cache

= Can I control how often the plugin scans for offloaded fonts? =

Yes. You can adjust the scan interval in the plugin's settings (Tools > Font Protection > Settings).

== Screenshots ==

1. Dashboard overview showing font statistics
2. Activity logs tracking all font protection actions
3. Settings page for customizing plugin behavior
4. Tools page with troubleshooting options
5. Page builder integration with Elementor and Bricks

== Changelog ==

= 2.0.0 =
* Major release with complete redesign of the user interface
* Added special support for Elementor and Bricks Builder
* Improved logging system with severity levels and filters
* Added tools for theme scanning and CSS generation
* Enhanced debugging capabilities
* Added email notifications for critical events
* Optimized background processing for better performance
* Added support for SVG font format

= 1.2.0 =
* Added improved debugging
* Enhanced URL fixing for various cloud providers
* Added additional font detection mechanisms

= 1.1.0 =
* Added dashboard for monitoring font status
* Improved font restoration process
* Fixed compatibility issues with some cloud providers

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 2.0.0 =
Major update with enhanced UI, Elementor and Bricks Builder support, and many new features. Please review the settings after upgrading.
