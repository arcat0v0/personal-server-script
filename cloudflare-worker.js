/**
 * Cloudflare Worker - GitHub Keys Proxy
 *
 * This worker acts as a reverse proxy for GitHub SSH keys.
 * It fetches keys from github.com/arcat0v0.keys and returns them.
 *
 * Deploy this to Cloudflare Workers and use the worker URL
 * instead of GitHub's URL when GitHub is not accessible.
 */

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // Only allow GET requests
  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 })
  }

  // GitHub username to fetch keys for
  const GITHUB_USERNAME = 'arcat0v0'
  const GITHUB_KEYS_URL = `https://github.com/${GITHUB_USERNAME}.keys`

  try {
    // Fetch keys from GitHub
    const response = await fetch(GITHUB_KEYS_URL, {
      headers: {
        'User-Agent': 'Cloudflare-Worker-Proxy/1.0'
      }
    })

    if (!response.ok) {
      return new Response(`Failed to fetch keys from GitHub: ${response.status}`, {
        status: response.status
      })
    }

    // Get the keys content
    const keys = await response.text()

    // Return the keys with appropriate headers
    return new Response(keys, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
        'Access-Control-Allow-Origin': '*',
        'X-Proxy-By': 'Cloudflare-Worker',
        'X-GitHub-Username': GITHUB_USERNAME
      }
    })
  } catch (error) {
    return new Response(`Error fetching keys: ${error.message}`, {
      status: 500,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8'
      }
    })
  }
}
