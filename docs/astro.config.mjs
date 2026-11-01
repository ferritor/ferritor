// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi';
import starlightLinksValidator from 'starlight-links-validator';
import starlightGitHubAlerts from 'starlight-github-alerts';
import starlightSeo from 'starlight-seo';

// https://astro.build/config
export default defineConfig({
	site: 'https://ferritor.dev',
	integrations: [
    starlight({
      plugins: [
        starlightLinksValidator(),
        starlightGitHubAlerts(),
        starlightSeo({
          image: '/og.png',
          publisher: {
            type: 'Organization',
            name: 'ferritor',
            url: 'https://ferritor.dev/',
            logo: 'https://ferritor.dev/android-chrome-512x512.png',
            sameAs: ['https://github.com/ferritor'],
          },
          // Each page's search title is its `seo.title`; the generated API pages
          // get theirs here.
          title: {
            templates: [
              { match: '/api/', template: 'ferritor JSON API reference: every endpoint' },
              { match: '/api/operations/tags/health/', template: 'ferritor JSON API: health and readiness' },
              { match: '/api/operations/tags/policies/', template: 'ferritor JSON API: stored policy endpoints' },
              { match: '/api/operations/tags/secrets/', template: 'ferritor JSON API: secret endpoints' },
            ],
          },
          audit: {
            rules: { 'title.duplicate': 'off', 'description.missing': 'off' }
          }
        }),
        starlightOpenAPI([
          {
            base: 'api',
            schema: 'openapi.json',
          },
        ]),
      ],
      title: 'ferritor',
      logo: {
        dark: './src/assets/brand/ferritor-horizontal-on-dark.svg',
        light: './src/assets/brand/ferritor-horizontal-on-light.svg',
        replacesTitle: true,
      },
      favicon: '/favicon.svg',
      // The rest of the brand's icons, in public/.
      head: [
        { tag: 'link', attrs: { rel: 'icon', href: '/favicon.ico', sizes: '48x48' } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
        { tag: 'link', attrs: { rel: 'manifest', href: '/site.webmanifest' } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#17191B' } },
      ],
      customCss: ['./src/styles/custom.css'],
			defaultLocale: 'en',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/ferritor/ferritor' }],
			editLink: { baseUrl: 'https://github.com/ferritor/ferritor/edit/main/docs/' },
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Quick start', slug: 'getting-started/quick-start' },
						{ label: 'Production deployment', slug: 'getting-started/production' },
						{ label: 'Kubernetes', slug: 'getting-started/kubernetes' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Architecture', slug: 'concepts/architecture' },
						{ label: 'Security model', slug: 'concepts/security' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Secrets', slug: 'guides/secrets' },
						{ label: 'Policy', slug: 'guides/policy' },
						{ label: 'TLS and identity', slug: 'guides/tls' },
						{ label: 'Workload identity', slug: 'guides/workload-identity' },
						{ label: 'The agent', slug: 'guides/agent' },
						{ label: 'The CSI provider', slug: 'guides/csi' },
					],
				},
				{
					label: 'Operations',
					items: [
						{ label: 'Operations', slug: 'operations/running' },
						{ label: 'Key management', slug: 'operations/key-management' },
						{ label: 'Audit log', slug: 'operations/audit' },
						{ label: 'Backup and restore', slug: 'operations/backup-restore' },
						{ label: 'High availability', slug: 'operations/high-availability' },
						{ label: 'Performance', slug: 'operations/performance' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Configuration', slug: 'reference/configuration' },
						{ label: 'HTTP API', slug: 'reference/http-api' },
					],
				},
				{
					label: 'Contributing',
					items: [{ label: 'Development', slug: 'contributing/development' }],
				},
				...openAPISidebarGroups
			],
		}),
	],
});
