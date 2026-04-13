import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { createDecipheriv } from 'node:crypto'

function solveChallengeCookie(html) {
  const match = html.match(/a=toNumbers\("([0-9a-f]+)"\),b=toNumbers\("([0-9a-f]+)"\),c=toNumbers\("([0-9a-f]+)"\)/i)
  if (!match) return null
  const [, keyHex, ivHex, cipherHex] = match
  const decipher = createDecipheriv('aes-128-cbc', Buffer.from(keyHex, 'hex'), Buffer.from(ivHex, 'hex'))
  decipher.setAutoPadding(false)
  const tokenHex = Buffer.concat([decipher.update(Buffer.from(cipherHex, 'hex')), decipher.final()]).toString('hex')
  return tokenHex
}

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'cheq-challenge-bypass',
      configureServer(server) {
        server.middlewares.use('/api/cheq-csv', async (_req, res) => {
          try {
            const baseUrl = 'https://cheq.free.nf/sample-traffic-data.csv'
            const first = await fetch(baseUrl)
            const firstText = await first.text()
            const cookie = solveChallengeCookie(firstText)

            const second = await fetch(`${baseUrl}?i=1`, {
              headers: cookie ? { cookie: `__test=${cookie}` } : {},
            })
            const secondText = await second.text()

            if (!second.ok || secondText.trim().startsWith('<')) {
              res.statusCode = 502
              res.setHeader('Content-Type', 'text/plain; charset=utf-8')
              res.end('Could not retrieve CSV from CHEQ endpoint')
              return
            }

            res.statusCode = 200
            res.setHeader('Content-Type', 'text/csv; charset=utf-8')
            res.end(secondText)
          } catch (err) {
            res.statusCode = 502
            res.setHeader('Content-Type', 'text/plain; charset=utf-8')
            res.end(`Proxy fetch failed: ${err.message}`)
          }
        })
      },
    },
  ],
  // GitHub Pages repo path (https://camerensmith.github.io/casestudycheq/)
  base: '/casestudycheq/',
})