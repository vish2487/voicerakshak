import { useEffect, useRef, useState } from 'react'

type HealthState = 'checking' | 'online' | 'offline'
type SourceType = 'call' | 'SMS' | 'WhatsApp' | 'other'
type Language = 'en-IN' | 'hi-IN' | 'mr-IN' | 'ta-IN'
type Risk = 'high' | 'caution' | 'insufficient_information'
type Indicator = { code: string; label: string; explanation: string }
type Assessment = {
  risk_classification: Risk
  matched_indicators: Indicator[]
  explanations: string[]
  recommended_actions: string[]
  clarifying_question: string | null
  safety_disclaimer: string
}

type SpeechResult = { isFinal: boolean; 0: { transcript: string } }
type SpeechRecognitionEvent = { resultIndex: number; results: ArrayLike<SpeechResult> }
type SpeechRecognitionErrorEvent = { error: string }
type Recognition = {
  lang: string
  continuous: boolean
  interimResults: boolean
  onresult: ((event: SpeechRecognitionEvent) => void) | null
  onerror: ((event: SpeechRecognitionErrorEvent) => void) | null
  onend: (() => void) | null
  start: () => void
  stop: () => void
}
type RecognitionConstructor = new () => Recognition
type SpeechWindow = Window & {
  SpeechRecognition?: RecognitionConstructor
  webkitSpeechRecognition?: RecognitionConstructor
}

const MAX_MESSAGE_LENGTH = 8000
const LANGUAGES: Array<{ value: Language; label: string }> = [
  { value: 'en-IN', label: 'English (India)' },
  { value: 'hi-IN', label: 'हिन्दी' },
  { value: 'mr-IN', label: 'मराठी' },
  { value: 'ta-IN', label: 'தமிழ்' },
]
const UI_COPY: Record<Language, Record<string, string>> = {
  'en-IN': {
    tagline: 'Pause. Verify. Stay in control.', eyebrow: 'A calmer way to answer the call', title: 'Trust your voice.', titleEm: 'Verify the caller.', intro: 'Scam calls can sound like someone you know. Pause, capture what was said, and check for warning signs.', safety: 'Never share an OTP, PIN, password, or banking credential here or with an unexpected caller.', cardTitle: 'Check a message', cardIntro: 'Speak or type what the caller or sender said.', speak: 'Speak Now', stop: 'Stop listening', language: 'Assessment language', speechDisclosure: 'Browser speech recognition may process audio externally. VoiceRakshak does not receive or save your audio.', transcript: 'Message or editable transcript', placeholder: 'Tap Speak Now or type the message here…', editHint: 'You can edit the transcript before analysis.', source: 'Where did you receive it?', analyse: 'Analyse message', analysing: 'Analysing…', privacy: 'Your message is sent to the assessment service for this check only. It is not saved by VoiceRakshak.', empty: 'Add a message or transcript before analysing it.', tooLong: 'Messages must be 8,000 characters or fewer.', apiValidation: 'The message could not be assessed. Check that it is not blank and is within the 8,000 character limit.', apiFailure: 'The assessment service could not complete this request. Please try again.', invalidResponse: 'The assessment service returned an unexpected response. Please try again.', network: 'Could not reach the assessment service. Check your connection and try again.', speechUnavailable: 'Speech recognition is not available in this browser. You can type or paste the message below.', micDenied: 'Microphone permission was not granted. You can type or paste the message instead.', speechError: 'Speech recognition stopped. You can edit the transcript or type the message instead.', localeUnsupported: 'The browser could not start speech recognition for this language. You can type or paste the message instead.', speechStart: 'Speech recognition could not start. You can type or paste the message instead.', hearing: 'Hearing:', assessment: 'ASSESSMENT', high: 'High risk signals found', caution: 'Use caution', insufficient: 'Insufficient information', warningSigns: 'Warning signs', meaning: 'What this means', recommended: 'Recommended actions', clarify: 'To understand more:', listen: 'Listen to guidance', noSignals: 'No listed warning pattern was found in the text provided. That does not confirm the message or caller is genuine.', safetyBasics: 'Safety basics', takeTime: 'Take your time', urgency: 'Urgency is a reason to slow down, not speed up.', check: 'Check independently', callback: 'Call back using a number you already trust.', control: 'Keep control', codeSafety: 'Never share a code or send money under pressure.', footer: 'Simple awareness for a safer conversation.', online: 'Service connected', offline: 'Service unavailable', checking: 'Checking service',
  },
  'hi-IN': {
    tagline: 'रुकें। जाँचें। नियंत्रण अपने हाथ में रखें।', eyebrow: 'कॉल का जवाब देने का शांत तरीका', title: 'अपनी समझ पर भरोसा रखें।', titleEm: 'कॉलर की पुष्टि करें।', intro: 'धोखाधड़ी वाली कॉल किसी परिचित की तरह लग सकती है। रुकें, कही गई बात लिखें और चेतावनी संकेत देखें।', safety: 'यहाँ या अनजान कॉलर के साथ OTP, PIN, पासवर्ड या बैंक जानकारी साझा न करें।', cardTitle: 'संदेश जाँचें', cardIntro: 'कॉलर या भेजने वाले की बात बोलें या लिखें।', speak: 'बोलना शुरू करें', stop: 'सुनना बंद करें', language: 'जाँच की भाषा', speechDisclosure: 'ब्राउज़र का वाक् पहचान फीचर ऑडियो को बाहरी रूप से संसाधित कर सकता है। VoiceRakshak आपका ऑडियो प्राप्त या सहेजता नहीं है।', transcript: 'संदेश या संपादन योग्य प्रतिलेख', placeholder: 'बोलना शुरू करें या संदेश यहाँ लिखें…', editHint: 'जाँच से पहले प्रतिलेख संपादित कर सकते हैं।', source: 'संदेश कहाँ मिला?', analyse: 'संदेश जाँचें', analysing: 'जाँच हो रही है…', privacy: 'संदेश केवल इस जाँच के लिए मूल्यांकन सेवा को भेजा जाता है। VoiceRakshak इसे सहेजता नहीं है।', empty: 'जाँच से पहले संदेश या प्रतिलेख लिखें।', tooLong: 'संदेश 8,000 अक्षरों से अधिक नहीं होना चाहिए।', apiValidation: 'संदेश की जाँच नहीं हो सकी। खाली संदेश और 8,000 अक्षरों की सीमा जाँचें।', apiFailure: 'मूल्यांकन सेवा यह अनुरोध पूरा नहीं कर सकी। फिर कोशिश करें।', invalidResponse: 'मूल्यांकन सेवा से अनपेक्षित जवाब मिला। फिर कोशिश करें।', network: 'मूल्यांकन सेवा तक पहुँचा नहीं जा सका। कनेक्शन जाँचकर फिर कोशिश करें।', speechUnavailable: 'इस ब्राउज़र में वाक् पहचान उपलब्ध नहीं है। नीचे संदेश लिख या चिपका सकते हैं।', micDenied: 'माइक्रोफ़ोन की अनुमति नहीं मिली। संदेश लिख या चिपका सकते हैं।', speechError: 'वाक् पहचान रुक गई। प्रतिलेख संपादित करें या संदेश लिखें।', localeUnsupported: 'ब्राउज़र इस भाषा में वाक् पहचान शुरू नहीं कर सका। संदेश लिख या चिपका सकते हैं।', speechStart: 'वाक् पहचान शुरू नहीं हो सकी। संदेश लिख या चिपका सकते हैं।', hearing: 'सुन रहा है:', assessment: 'मूल्यांकन', high: 'उच्च जोखिम के संकेत मिले', caution: 'सावधानी रखें', insufficient: 'जानकारी अपर्याप्त है', warningSigns: 'चेतावनी संकेत', meaning: 'इसका अर्थ', recommended: 'सुझाए गए कदम', clarify: 'और जानने के लिए:', listen: 'मार्गदर्शन सुनें', noSignals: 'दिए गए पाठ में पहचाना गया चेतावनी संकेत नहीं मिला। इससे संदेश या कॉलर की असलियत साबित नहीं होती।', safetyBasics: 'सुरक्षा के तरीके', takeTime: 'समय लें', urgency: 'जल्दबाज़ी का दबाव हो तो रुकें।', check: 'स्वतंत्र रूप से जाँचें', callback: 'पहले से ज्ञात नंबर पर वापस कॉल करें।', control: 'नियंत्रण अपने हाथ में रखें', codeSafety: 'दबाव में कोड साझा न करें या पैसे न भेजें।', footer: 'सुरक्षित बातचीत के लिए सरल जानकारी।', online: 'सेवा जुड़ी है', offline: 'सेवा उपलब्ध नहीं', checking: 'सेवा जाँची जा रही है',
  },
  'mr-IN': {
    tagline: 'थांबा. खात्री करा. नियंत्रण ठेवा.', eyebrow: 'कॉलला उत्तर देण्याचा शांत मार्ग', title: 'स्वतःच्या निर्णयावर विश्वास ठेवा.', titleEm: 'कॉलरची खात्री करा.', intro: 'फसवणुकीचा कॉल ओळखीच्या व्यक्तीसारखा वाटू शकतो. थांबा, काय सांगितले ते नोंदवा आणि इशारे तपासा.', safety: 'येथे किंवा अनोळखी कॉलरसोबत OTP, PIN, पासवर्ड किंवा बँक तपशील शेअर करू नका.', cardTitle: 'संदेश तपासा', cardIntro: 'कॉलर किंवा पाठवणाऱ्याने काय सांगितले ते बोला किंवा लिहा.', speak: 'बोलणे सुरू करा', stop: 'ऐकणे थांबवा', language: 'तपासणीची भाषा', speechDisclosure: 'ब्राउझरचे वाक्-ओळख वैशिष्ट्य ऑडिओ बाहेर प्रक्रिया करू शकते. VoiceRakshak तुमचा ऑडिओ घेत किंवा साठवत नाही.', transcript: 'संदेश किंवा संपादनयोग्य मजकूर', placeholder: 'बोलणे सुरू करा किंवा संदेश येथे टाइप करा…', editHint: 'तपासण्यापूर्वी मजकूर संपादित करू शकता.', source: 'संदेश कुठे मिळाला?', analyse: 'संदेश तपासा', analysing: 'तपासत आहे…', privacy: 'संदेश फक्त या तपासणीसाठी मूल्यांकन सेवेकडे पाठवला जातो. VoiceRakshak तो साठवत नाही.', empty: 'तपासण्यापूर्वी संदेश किंवा मजकूर जोडा.', tooLong: 'संदेश 8,000 अक्षरांपेक्षा मोठा नसावा.', apiValidation: 'संदेश तपासता आला नाही. रिकामा मजकूर आणि 8,000 अक्षरांची मर्यादा तपासा.', apiFailure: 'मूल्यांकन सेवा ही विनंती पूर्ण करू शकली नाही. पुन्हा प्रयत्न करा.', invalidResponse: 'मूल्यांकन सेवेकडून अनपेक्षित उत्तर मिळाले. पुन्हा प्रयत्न करा.', network: 'मूल्यांकन सेवेशी संपर्क झाला नाही. कनेक्शन तपासून पुन्हा प्रयत्न करा.', speechUnavailable: 'या ब्राउझरमध्ये वाक्-ओळख उपलब्ध नाही. खाली संदेश टाइप किंवा पेस्ट करा.', micDenied: 'मायक्रोफोनची परवानगी मिळाली नाही. संदेश टाइप किंवा पेस्ट करा.', speechError: 'वाक्-ओळख थांबली. मजकूर संपादित करा किंवा टाइप करा.', localeUnsupported: 'ब्राउझरला या भाषेत वाक्-ओळख सुरू करता आली नाही. संदेश टाइप किंवा पेस्ट करा.', speechStart: 'वाक्-ओळख सुरू झाली नाही. संदेश टाइप किंवा पेस्ट करा.', hearing: 'ऐकत आहे:', assessment: 'तपासणी', high: 'उच्च जोखमीचे संकेत आढळले', caution: 'सावध राहा', insufficient: 'माहिती अपुरी आहे', warningSigns: 'इशारे', meaning: 'याचा अर्थ', recommended: 'सुचवलेली पावले', clarify: 'अधिक समजण्यासाठी:', listen: 'मार्गदर्शन ऐका', noSignals: 'दिलेल्या मजकुरात सूचीबद्ध इशारा आढळला नाही. यामुळे संदेश किंवा कॉलर खरा असल्याचे सिद्ध होत नाही.', safetyBasics: 'सुरक्षिततेचे उपाय', takeTime: 'वेळ घ्या', urgency: 'घाईचा दबाव असेल तर थांबा.', check: 'स्वतंत्रपणे तपासा', callback: 'आधीपासून माहीत असलेल्या क्रमांकावर परत कॉल करा.', control: 'नियंत्रण ठेवा', codeSafety: 'दबावाखाली कोड शेअर करू नका किंवा पैसे पाठवू नका.', footer: 'सुरक्षित संभाषणासाठी सोपी माहिती.', online: 'सेवा जोडली आहे', offline: 'सेवा उपलब्ध नाही', checking: 'सेवा तपासत आहे',
  },
  'ta-IN': {
    tagline: 'நிறுத்துங்கள். சரிபாருங்கள். கட்டுப்பாட்டில் இருங்கள்.', eyebrow: 'அழைப்பை அமைதியாக எதிர்கொள்ளுங்கள்', title: 'உங்கள் உள்ளுணர்வை நம்புங்கள்.', titleEm: 'அழைப்பவரைச் சரிபாருங்கள்.', intro: 'மோசடி அழைப்புகள் தெரிந்தவரைப் போல இருக்கலாம். நிறுத்தி, கூறியதைப் பதிவு செய்து எச்சரிக்கை அறிகுறிகளைப் பாருங்கள்.', safety: 'இங்கேயோ எதிர்பாராத அழைப்பவரிடமோ OTP, PIN, கடவுச்சொல் அல்லது வங்கி விவரங்களைப் பகிர வேண்டாம்.', cardTitle: 'செய்தியைச் சரிபார்க்கவும்', cardIntro: 'அழைப்பவர் அல்லது அனுப்பியவர் கூறியதைப் பேசுங்கள் அல்லது தட்டச்சு செய்யுங்கள்.', speak: 'பேசத் தொடங்கு', stop: 'கேட்பதை நிறுத்து', language: 'மதிப்பீட்டு மொழி', speechDisclosure: 'உலாவியின் பேச்சு அறிதல் ஒலியை வெளிப்புறமாகச் செயலாக்கலாம். VoiceRakshak உங்கள் ஒலியைப் பெறவோ சேமிக்கவோ செய்யாது.', transcript: 'செய்தி அல்லது திருத்தக்கூடிய உரை', placeholder: 'பேசத் தொடங்குங்கள் அல்லது செய்தியை இங்கே தட்டச்சு செய்யுங்கள்…', editHint: 'மதிப்பீட்டிற்கு முன் உரையைத் திருத்தலாம்.', source: 'செய்தி எங்கு வந்தது?', analyse: 'செய்தியை மதிப்பிடு', analysing: 'மதிப்பிடுகிறது…', privacy: 'இந்தச் சரிபார்ப்புக்காக மட்டும் செய்தி மதிப்பீட்டு சேவைக்கு அனுப்பப்படுகிறது. VoiceRakshak அதைச் சேமிக்காது.', empty: 'மதிப்பிடுவதற்கு முன் செய்தி அல்லது உரையைச் சேர்க்கவும்.', tooLong: 'செய்தி 8,000 எழுத்துகளுக்குள் இருக்க வேண்டும்.', apiValidation: 'செய்தியை மதிப்பிட முடியவில்லை. காலியாக இல்லையா, 8,000 எழுத்துகளுக்குள் உள்ளதா எனப் பார்க்கவும்.', apiFailure: 'மதிப்பீட்டு சேவை கோரிக்கையை நிறைவேற்றவில்லை. மீண்டும் முயற்சிக்கவும்.', invalidResponse: 'மதிப்பீட்டு சேவையிலிருந்து எதிர்பாராத பதில் வந்தது. மீண்டும் முயற்சிக்கவும்.', network: 'மதிப்பீட்டு சேவையை அணுக முடியவில்லை. இணைப்பைச் சரிபார்த்து மீண்டும் முயற்சிக்கவும்.', speechUnavailable: 'இந்த உலாவியில் பேச்சு அறிதல் இல்லை. கீழே தட்டச்சு செய்யலாம் அல்லது ஒட்டலாம்.', micDenied: 'மைக்ரோஃபோன் அனுமதி இல்லை. செய்தியைத் தட்டச்சு செய்யலாம் அல்லது ஒட்டலாம்.', speechError: 'பேச்சு அறிதல் நின்றுவிட்டது. உரையைத் திருத்தவும் அல்லது தட்டச்சு செய்யவும்.', localeUnsupported: 'இந்த மொழியில் பேச்சு அறிதலை உலாவி தொடங்க முடியவில்லை. செய்தியைத் தட்டச்சு செய்யலாம் அல்லது ஒட்டலாம்.', speechStart: 'பேச்சு அறிதலைத் தொடங்க முடியவில்லை. செய்தியைத் தட்டச்சு செய்யலாம் அல்லது ஒட்டலாம்.', hearing: 'கேட்கிறது:', assessment: 'மதிப்பீடு', high: 'அதிக ஆபத்து அறிகுறிகள் உள்ளன', caution: 'எச்சரிக்கையுடன் இருங்கள்', insufficient: 'தகவல் போதவில்லை', warningSigns: 'எச்சரிக்கை அறிகுறிகள்', meaning: 'இதன் பொருள்', recommended: 'பரிந்துரைக்கப்படும் செயல்கள்', clarify: 'மேலும் புரிந்துகொள்ள:', listen: 'வழிகாட்டுதலைக் கேளுங்கள்', noSignals: 'கொடுக்கப்பட்ட உரையில் பட்டியலிடப்பட்ட எச்சரிக்கை முறை இல்லை. இதனால் செய்தி அல்லது அழைப்பவர் உண்மையானவர் என உறுதி செய்ய முடியாது.', safetyBasics: 'பாதுகாப்பு வழிகள்', takeTime: 'நேரம் எடுத்துக்கொள்ளுங்கள்', urgency: 'அவசரப்படுத்தினால் நிறுத்தி யோசியுங்கள்.', check: 'தனியாகச் சரிபாருங்கள்', callback: 'ஏற்கனவே அறிந்த எண்ணில் திரும்ப அழையுங்கள்.', control: 'கட்டுப்பாட்டில் இருங்கள்', codeSafety: 'அழுத்தத்தில் குறியீட்டைப் பகிரவோ பணம் அனுப்பவோ வேண்டாம்.', footer: 'பாதுகாப்பான உரையாடலுக்கான எளிய விழிப்புணர்வு.', online: 'சேவை இணைக்கப்பட்டுள்ளது', offline: 'சேவை கிடைக்கவில்லை', checking: 'சேவையைச் சரிபார்க்கிறது',
  },
}
const SOURCE_OPTIONS: Array<{ value: SourceType; labels: Record<Language, string> }> = [
  { value: 'call', labels: { 'en-IN': 'Phone call', 'hi-IN': 'फ़ोन कॉल', 'mr-IN': 'फोन कॉल', 'ta-IN': 'தொலைபேசி அழைப்பு' } },
  { value: 'SMS', labels: { 'en-IN': 'SMS', 'hi-IN': 'SMS', 'mr-IN': 'SMS', 'ta-IN': 'SMS' } },
  { value: 'WhatsApp', labels: { 'en-IN': 'WhatsApp', 'hi-IN': 'WhatsApp', 'mr-IN': 'WhatsApp', 'ta-IN': 'WhatsApp' } },
  { value: 'other', labels: { 'en-IN': 'Other', 'hi-IN': 'अन्य', 'mr-IN': 'इतर', 'ta-IN': 'மற்றவை' } },
]

function isAssessment(value: unknown): value is Assessment {
  if (!value || typeof value !== 'object') return false
  const body = value as Partial<Assessment>
  return ['high', 'caution', 'insufficient_information'].includes(body.risk_classification ?? '')
    && Array.isArray(body.matched_indicators)
    && body.matched_indicators.every((item) => item && typeof item.code === 'string' && typeof item.label === 'string' && typeof item.explanation === 'string')
    && Array.isArray(body.explanations) && body.explanations.every((item) => typeof item === 'string')
    && Array.isArray(body.recommended_actions) && body.recommended_actions.every((item) => typeof item === 'string')
    && (typeof body.clarifying_question === 'string' || body.clarifying_question === null)
    && typeof body.safety_disclaimer === 'string'
}

function ShieldMark() {
  return <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 32 36" fill="none"><path d="M16 2.5 28 7v9.1c0 8.2-4.9 13.8-12 17.4C8.9 29.9 4 24.3 4 16.1V7l12-4.5Z" stroke="currentColor" strokeWidth="2.4"/><path d="M10 16.2h3.3l2.1-4.5 3.2 9 2.1-4.5H23" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round"/></svg></span>
}

function App() {
  const [health, setHealth] = useState<HealthState>('checking')
  const [message, setMessage] = useState('')
  const [sourceType, setSourceType] = useState<SourceType>('call')
  const [language, setLanguage] = useState<Language>('en-IN')
  const copy = UI_COPY[language]
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [listening, setListening] = useState(false)
  const [speechMessage, setSpeechMessage] = useState('')
  const [interim, setInterim] = useState('')
  const recognitionRef = useRef<Recognition | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/health', { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then((data: { status?: string }) => setHealth(data.status === 'ok' ? 'online' : 'offline'))
      .catch(() => { if (!controller.signal.aborted) setHealth('offline') })
    return () => {
      controller.abort()
      recognitionRef.current?.stop()
      window.speechSynthesis?.cancel()
    }
  }, [])

  function startListening() {
    setSpeechMessage('')
    const speechWindow = window as SpeechWindow
    const RecognitionApi = speechWindow.SpeechRecognition ?? speechWindow.webkitSpeechRecognition
    if (!RecognitionApi) {
      setSpeechMessage(copy.speechUnavailable)
      return
    }
    const recognition = new RecognitionApi()
    recognition.lang = language
    recognition.continuous = true
    recognition.interimResults = true
    recognition.onresult = (event) => {
      let finalText = ''
      let interimText = ''
      for (let index = event.resultIndex; index < event.results.length; index += 1) {
        const result = event.results[index]
        if (result.isFinal) finalText += result[0].transcript
        else interimText += result[0].transcript
      }
      if (finalText) setMessage((current) => `${current}${current && !current.endsWith(' ') ? ' ' : ''}${finalText.trim()}`.slice(0, MAX_MESSAGE_LENGTH))
      setInterim(interimText)
    }
    recognition.onerror = (event) => {
      setListening(false)
      setSpeechMessage(event.error === 'not-allowed' ? copy.micDenied
        : event.error === 'language-not-supported' ? copy.localeUnsupported : copy.speechError)
    }
    recognition.onend = () => { setListening(false); setInterim('') }
    recognitionRef.current = recognition
    try {
      recognition.start()
      setListening(true)
    } catch {
      setListening(false)
      setSpeechMessage(copy.speechStart)
    }
  }

  function stopListening() {
    recognitionRef.current?.stop()
    setListening(false)
    setInterim('')
  }

  async function analyseMessage(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setAssessment(null)
    if (!message.trim()) {
      setError(copy.empty)
      return
    }
    if (message.length > MAX_MESSAGE_LENGTH) {
      setError(copy.tooLong)
      return
    }
    setLoading(true)
    try {
      let response: Response
      try {
        response = await fetch('/api/assess', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message, source_type: sourceType, language }),
        })
      } catch {
        throw new Error(copy.network)
      }
      if (!response.ok) {
        if (response.status === 422) throw new Error(copy.apiValidation)
        throw new Error(copy.apiFailure)
      }
      const body: unknown = await response.json()
      if (!isAssessment(body)) throw new Error(copy.invalidResponse)
      setAssessment(body)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : copy.network)
    } finally {
      setLoading(false)
    }
  }

  function listenToGuidance() {
    if (!assessment || !('speechSynthesis' in window)) return
    window.speechSynthesis.cancel()
    const guidance = [...assessment.explanations, ...assessment.recommended_actions, assessment.safety_disclaimer].join('. ')
    const utterance = new SpeechSynthesisUtterance(guidance)
    utterance.lang = language
    window.speechSynthesis.speak(utterance)
  }

  return (
    <main>
      <header className="site-header">
        <a className="brand" href="#home" aria-label="VoiceRakshak home"><ShieldMark /><span className="brand-name">voice<span>rakshak</span><small>AI</small></span></a>
        <span className="header-tagline">{copy.tagline}</span>
      </header>

      <section className="hero" id="home">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> {copy.eyebrow}</div>
          <h1>{copy.title}<br /><em>{copy.titleEm}</em></h1>
          <p className="hero-intro">{copy.intro}</p>
          <p className="hero-safety">{copy.safety}</p>
        </div>
        <form className="assessment-card" onSubmit={analyseMessage}>
          <div className="card-heading"><span className="card-icon"><ShieldMark /></span><div><h2>{copy.cardTitle}</h2><p>{copy.cardIntro}</p></div></div>
          <button className={`speak-button${listening ? ' listening' : ''}`} type="button" onClick={listening ? stopListening : startListening} aria-pressed={listening}>
            <span className="mic-icon" aria-hidden="true">{listening ? '■' : '●'}</span>{listening ? copy.stop : copy.speak}
          </button>
          <label className="language-field" htmlFor="language">{copy.language}<select id="language" value={language} disabled={loading} onChange={(event) => { stopListening(); setLanguage(event.target.value as Language); setAssessment(null); setError('') }}>{LANGUAGES.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}</select></label>
          <div className="speech-note" aria-live="polite">{speechMessage || copy.speechDisclosure}</div>
          <label className="field-label" htmlFor="transcript">{copy.transcript}</label>
          <textarea id="transcript" value={message} onChange={(event) => setMessage(event.target.value)} placeholder={copy.placeholder} maxLength={MAX_MESSAGE_LENGTH + 1} rows={5} />
          <div className="transcript-meta"><span>{interim && listening ? `${copy.hearing} ${interim}` : copy.editHint}</span><span>{message.length.toLocaleString()} / {MAX_MESSAGE_LENGTH.toLocaleString()}</span></div>
          <label className="field-label" htmlFor="source-type">{copy.source}</label>
          <select id="source-type" value={sourceType} onChange={(event) => setSourceType(event.target.value as SourceType)}>
            {SOURCE_OPTIONS.map((option) => <option value={option.value} key={option.value}>{option.labels[language]}</option>)}
          </select>
          <button className="analyse-button" type="submit" disabled={loading}>{loading ? <><span className="spinner" aria-hidden="true" /> {copy.analysing}</> : <>{copy.analyse} <span aria-hidden="true">→</span></>}</button>
          <p className="privacy-notice"><span aria-hidden="true">⌑</span> {copy.privacy}</p>
          {error && <p className="form-error" role="alert">{error}</p>}
        </form>
      </section>

      {assessment && <section className={`results ${assessment.risk_classification}`} aria-labelledby="results-title" aria-live="polite">
        <div className="results-header"><div><span className="section-kicker">{copy.assessment}</span><h2 id="results-title">{assessment.risk_classification === 'high' ? copy.high : assessment.risk_classification === 'caution' ? copy.caution : copy.insufficient}</h2></div>
          {'speechSynthesis' in window && <button className="listen-button" type="button" onClick={listenToGuidance}>▶ {copy.listen} <span>· {LANGUAGES.find((item) => item.value === language)?.label}</span></button>}
        </div>
        {assessment.matched_indicators.length > 0 ? <div className="warning-list"><h3>{copy.warningSigns}</h3>{assessment.matched_indicators.map((indicator) => <article className="warning-item" key={indicator.code}><span className="warning-mark" aria-hidden="true">!</span><div><h4>{indicator.label}</h4><p>{indicator.explanation}</p></div></article>)}</div> : <p className="no-signals">{copy.noSignals}</p>}
        {assessment.explanations.length > 0 && <div className="explanations"><h3>{copy.meaning}</h3><ul>{assessment.explanations.map((explanation, index) => <li key={`${index}-${explanation}`}>{explanation}</li>)}</ul></div>}
        <div className="recommended"><h3>{copy.recommended}</h3><ul>{assessment.recommended_actions.map((action, index) => <li key={`${index}-${action}`}>{action}</li>)}</ul></div>
        {assessment.clarifying_question && <p className="clarifying-question"><strong>{copy.clarify}</strong> {assessment.clarifying_question}</p>}
        <p className="disclaimer">{assessment.safety_disclaimer}</p>
      </section>}

      <section className="principles" aria-label={copy.safetyBasics}>
        <div className="principle"><span className="principle-icon">◷</span><div><h2>{copy.takeTime}</h2><p>{copy.urgency}</p></div></div>
        <div className="principle"><span className="principle-icon">◎</span><div><h2>{copy.check}</h2><p>{copy.callback}</p></div></div>
        <div className="principle"><span className="principle-icon">◇</span><div><h2>{copy.control}</h2><p>{copy.codeSafety}</p></div></div>
      </section>
      <footer className="site-footer"><a className="brand footer-brand" href="#home"><ShieldMark /><span className="brand-name">voice<span>rakshak</span><small>AI</small></span></a><span className="footer-note">{copy.footer}</span><span className={`health-status ${health}`} role="status"><i />{health === 'checking' ? copy.checking : health === 'online' ? copy.online : copy.offline}</span></footer>
    </main>
  )
}

export default App
