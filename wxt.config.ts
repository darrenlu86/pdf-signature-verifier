import { defineConfig } from 'wxt'

export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-react'],
  manifest: ({ browser }) => ({
    name: 'PDFtrust - PDF 數位簽章驗證工具',
    description: 'Verify PDF digital signatures — integrity, certificate chain, trust, timestamp, revocation & LTV. Supports global CAs.',
    version: '1.0.0',
    permissions: ['activeTab', 'storage', 'downloads'],
    host_permissions: ['<all_urls>'],
    icons: {
      16: 'icon-16.png',
      32: 'icon-32.png',
      48: 'icon-48.png',
      128: 'icon-128.png',
    },
    web_accessible_resources: [
      {
        resources: ['panel.html', 'chunks/*', 'assets/*'],
        matches: ['<all_urls>'],
      },
    ],
    browser_specific_settings: browser === 'firefox'
      ? {
          gecko: {
            id: 'pdftrust@darrenlu.com',
            strict_min_version: '109.0',
            data_collection_permissions: {
              required: ['none'],
            },
          },
        }
      : undefined,
  }),
  runner: {
    startUrls: ['https://example.com'],
  },
})
