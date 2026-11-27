import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from './App'

const assessment = {
  risk_classification: 'high',
  matched_indicators: [{ code: 'credential_harvesting', label: 'Request for a sensitive credential', explanation: 'The text asks for a one-time code.' }],
  explanations: ['The text asks for a one-time code.'],
  recommended_actions: ['Do not share the code.'],
  clarifying_question: null,
  safety_disclaimer: 'This is a limited safety aid.',
}

function jsonResponse(body: unknown, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body }
}

describe('VoiceRakshak assessment interface', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ status: 'ok' })))
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('shows branding, supported language, source choices, privacy guidance and health status', async () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: /trust your voice/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /speak now/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /assessment language/i })).toHaveValue('en-IN')
    expect(screen.getAllByRole('option')).toHaveLength(8)
    expect(screen.getByRole('option', { name: 'English (India)' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /where did you receive it/i }).querySelectorAll('option')).toHaveLength(4)
    expect(screen.getByText(/browser speech recognition may process audio externally/i)).toBeInTheDocument()
    expect(await screen.findByRole('status')).toHaveTextContent('Service connected')
  })

  it('validates empty input without calling the assessment API', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /analyse message/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Add a message')
    expect(fetch).not.toHaveBeenCalledWith('/api/assess', expect.anything())
  })

  it('rejects text over the backend character limit before making a request', async () => {
    render(<App />)
    fireEvent.change(screen.getByLabelText(/message or editable transcript/i), { target: { value: 'x'.repeat(8001) } })
    fireEvent.click(screen.getByRole('button', { name: /analyse message/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/8,000 characters or fewer/i)
    expect(fetch).not.toHaveBeenCalledWith('/api/assess', expect.anything())
  })

  it('sends the actual API request schema and renders the backend assessment', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => String(input) === '/api/health'
      ? jsonResponse({ status: 'ok' }) as Response
      : jsonResponse(assessment) as Response)
    render(<App />)
    fireEvent.change(screen.getByLabelText(/message or editable transcript/i), { target: { value: 'Send me your OTP.' } })
    fireEvent.change(screen.getByLabelText(/where did you receive it/i), { target: { value: 'WhatsApp' } })
    fireEvent.click(screen.getByRole('button', { name: /analyse message/i }))

    expect(await screen.findByRole('heading', { name: 'High risk signals found' })).toBeInTheDocument()
    expect(screen.getByText('Request for a sensitive credential')).toBeInTheDocument()
    expect(screen.getByText('Do not share the code.')).toBeInTheDocument()
    const assessCall = vi.mocked(fetch).mock.calls.find(([url]) => url === '/api/assess')
    expect(assessCall?.[1]).toMatchObject({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'Send me your OTP.', source_type: 'WhatsApp', language: 'en-IN' }),
    })
  })

  it('shows a loading state until the API responds', async () => {
    let resolveRequest: ((response: Response) => void) | undefined
    vi.mocked(fetch).mockImplementation((input) => String(input) === '/api/health'
      ? Promise.resolve(jsonResponse({ status: 'ok' }) as Response)
      : new Promise((resolve) => { resolveRequest = resolve }))
    render(<App />)
    fireEvent.change(screen.getByLabelText(/message or editable transcript/i), { target: { value: 'Test message' } })
    fireEvent.click(screen.getByRole('button', { name: /analyse message/i }))

    expect(screen.getByRole('button', { name: /analysing/i })).toBeDisabled()
    await act(async () => { resolveRequest?.(jsonResponse(assessment) as Response) })
    expect(await screen.findByRole('heading', { name: 'High risk signals found' })).toBeInTheDocument()
  })

  it('shows network and API validation errors without inventing a result', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => String(input) === '/api/health'
      ? jsonResponse({ status: 'ok' }) as Response
      : Promise.reject(new Error('offline')))
    const { rerender } = render(<App />)
    fireEvent.change(screen.getByLabelText(/message or editable transcript/i), { target: { value: 'Test message' } })
    fireEvent.click(screen.getByRole('button', { name: /analyse message/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not reach the assessment service/i)
    expect(screen.queryByRole('heading', { name: /risk signals found|use caution|insufficient information/i })).not.toBeInTheDocument()

    vi.mocked(fetch).mockImplementation(async (input) => String(input) === '/api/health'
      ? jsonResponse({ status: 'ok' }) as Response
      : jsonResponse({ detail: 'invalid' }, 422) as Response)
    rerender(<App />)
    fireEvent.click(screen.getByRole('button', { name: /analyse message/i }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/could not be assessed/i))
  })

  it('starts speech only after the Speak Now click and puts final transcript in the editable field', async () => {
    const recognitionInstances: Array<{ lang: string; start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn>; onresult: ((event: { resultIndex: number; results: ArrayLike<{ isFinal: boolean; 0: { transcript: string } }> }) => void) | null }> = []
    class MockRecognition {
      lang = ''
      continuous = false
      interimResults = false
      onresult: ((event: { resultIndex: number; results: ArrayLike<{ isFinal: boolean; 0: { transcript: string } }> }) => void) | null = null
      onerror = null
      onend = null
      start = vi.fn()
      stop = vi.fn()
      constructor() { recognitionInstances.push(this) }
    }
    vi.stubGlobal('SpeechRecognition', MockRecognition)
    render(<App />)

    expect(recognitionInstances).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: /speak now/i }))
    expect(recognitionInstances).toHaveLength(1)
    expect(recognitionInstances[0].start).toHaveBeenCalledOnce()
    expect(recognitionInstances[0].lang).toBe('en-IN')
    act(() => recognitionInstances[0].onresult?.({ resultIndex: 0, results: [{ isFinal: true, 0: { transcript: 'Transfer the money now.' } }] }))
    expect(screen.getByLabelText(/message or editable transcript/i)).toHaveValue('Transfer the money now.')
  })

  it('sends the selected locale and uses it for speech recognition and synthesized guidance', async () => {
    const hindiAssessment = {
      risk_classification: 'high',
      matched_indicators: [{ code: 'credential_harvesting', label: 'संवेदनशील जानकारी माँगी जा रही है', explanation: 'संदेश में OTP बताने को कहा गया है।' }],
      explanations: ['संदेश में OTP बताने को कहा गया है।'],
      recommended_actions: ['OTP साझा न करें।'],
      clarifying_question: null,
      safety_disclaimer: 'यह सीमित सुरक्षा सहायता है।',
    }
    vi.mocked(fetch).mockImplementation(async (input) => String(input) === '/api/health'
      ? jsonResponse({ status: 'ok' }) as Response
      : jsonResponse(hindiAssessment) as Response)
    const recognitionInstances: Array<{ lang: string; start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn> }> = []
    class MockRecognition {
      lang = ''
      continuous = false
      interimResults = false
      onresult = null
      onerror = null
      onend = null
      start = vi.fn()
      stop = vi.fn()
      constructor() { recognitionInstances.push(this) }
    }
    const speechSynthesis = { cancel: vi.fn(), speak: vi.fn() }
    const utterances: Array<{ text: string; lang: string }> = []
    class MockUtterance {
      lang = ''
      constructor(public text: string) { utterances.push(this) }
    }
    vi.stubGlobal('SpeechRecognition', MockRecognition)
    vi.stubGlobal('speechSynthesis', speechSynthesis)
    vi.stubGlobal('SpeechSynthesisUtterance', MockUtterance)
    render(<App />)
    fireEvent.change(screen.getByLabelText(/assessment language/i), { target: { value: 'hi-IN' } })
    fireEvent.click(screen.getByRole('button', { name: /बोलना शुरू करें/i }))
    expect(recognitionInstances[0].lang).toBe('hi-IN')
    fireEvent.change(screen.getByLabelText('संदेश या संपादन योग्य प्रतिलेख'), { target: { value: 'अपना OTP बताएं।' } })
    fireEvent.click(screen.getByRole('button', { name: /संदेश जाँचें/i }))

    expect(await screen.findByRole('heading', { name: 'उच्च जोखिम के संकेत मिले' })).toBeInTheDocument()
    expect(screen.getByText('संवेदनशील जानकारी माँगी जा रही है')).toBeInTheDocument()
    const assessCall = vi.mocked(fetch).mock.calls.find(([url]) => url === '/api/assess')
    expect(JSON.parse(String(assessCall?.[1]?.body))).toMatchObject({ message: 'अपना OTP बताएं।', language: 'hi-IN' })
    fireEvent.click(screen.getByRole('button', { name: /मार्गदर्शन सुनें/i }))
    expect(utterances[0].lang).toBe('hi-IN')
    expect(speechSynthesis.speak).toHaveBeenCalledOnce()
  })

  it('offers typed fallback when speech recognition is unavailable', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /speak now/i }))

    expect(screen.getByText(/speech recognition is not available/i)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/message or editable transcript/i), { target: { value: 'Typed fallback content' } })
    expect(screen.getByLabelText(/message or editable transcript/i)).toHaveValue('Typed fallback content')
  })

  it('reports when the backend health check cannot be reached', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    render(<App />)
    expect(await screen.findByRole('status')).toHaveTextContent('Service unavailable')
  })
})
