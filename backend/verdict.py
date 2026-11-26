"""Rule-based risk scoring, plain-language verdict, cybercrime report generator, and ElevenLabs TTS."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.security import defang_url

logger = logging.getLogger("scam_soc.verdict")

ELEVENLABS_DEFAULT_VOICE_ID = "21m00Tcm4TlvDq8ikWAM"
ELEVENLABS_DEFAULT_MODEL_ID = "eleven_multilingual_v2"
ELEVENLABS_TIMEOUT_SECONDS = 15.0
AUDIO_CACHE_TTL_SECONDS = 3600.0

_AUDIO_CACHE: dict[str, tuple[float, str]] = {}

_FIELD_PLAIN_LABELS: dict[str, str] = {
    "password": "password",
    "otp": "OTP",
    "pin": "PIN",
    "card": "card number",
    "cvv": "CVV",
    "aadhaar": "Aadhaar number",
    "upi": "UPI details",
}

SUPPORTED_LANGUAGE_NAMES: dict[str, str] = {
    "en": "English",
    "hi": "Hindi",
    "kn": "Kannada",
    "ta": "Tamil",
    "te": "Telugu",
    "ml": "Malayalam",
    "mr": "Marathi",
    "bn": "Bengali",
    "gu": "Gujarati",
    "pa": "Punjabi",
    "ur": "Urdu",
    "ar": "Arabic",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "ja": "Japanese",
    "ko": "Korean",
    "pt": "Portuguese",
    "id": "Indonesian",
    "vi": "Vietnamese",
    "tr": "Turkish",
    "ru": "Russian",
    "it": "Italian",
    "nl": "Dutch",
    "pl": "Polish",
}

_SPOKEN_SCRIPTS: dict[str, dict[str, str]] = {
    "en": {
        "DANGEROUS": (
            "This link looks dangerous and shows clear signs of a scam trying to steal your money or personal details. "
            "Please delete this message right away, never share your OTP or UPI PIN, and report it by calling 1930 or using the Chakshu portal."
        ),
        "SUSPICIOUS": (
            "This link looks suspicious and has warning signs that do not match a trusted official service. "
            "Do not enter any OTP, PIN, or payment details here; delete the message and report it to 1930 or the Chakshu portal if you are unsure."
        ),
        "SAFE": (
            "We did not find obvious scam traps or risky payment requests on this link. "
            "Even so, never share your OTP or PIN, and always double-check important bills or alerts directly inside the official app."
        ),
        "APK_TRAP": (
            "Warning! This link is a dangerous phone virus trap that tries to download a fake app to steal your bank OTPs. "
            "Do not install anything, delete this message immediately, and report the sender on 1930 or the Chakshu portal."
        ),
    },
    "kn": {
        "DANGEROUS": (
            "ಈ ಲಿಂಕ್ ಅಪಾಯಕಾರಿಯಾಗಿದ್ದು ನಿಮ್ಮ ಹಣ ಅಥವಾ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ಕದಿಯುವ ವಂಚನೆಯ ಲಕ್ಷಣಗಳನ್ನು ತೋರಿಸುತ್ತಿದೆ. "
            "ದಯವಿಟ್ಟು ಈ ಸಂದೇಶವನ್ನು ತಕ್ಷಣ ಅಳಿಸಿ, ನಿಮ್ಮ ಒಟಿಪಿ ಅಥವಾ ಯುಪಿಐ ಪಿನ್ ಅನ್ನು ಎಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ, ಮತ್ತು 1930 ಗೆ ಕರೆ ಮಾಡಿ ಅಥವಾ ಚಕ್ಷು ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ದೂರು ನೀಡಿ."
        ),
        "SUSPICIOUS": (
            "ಈ ಲಿಂಕ್ ಅನುಮಾನಾಸ್ಪದವಾಗಿದ್ದು ಅಧಿಕೃತ ಸೇವೆಯಂತೆ ಕಾಣದ ಎಚ್ಚರಿಕೆಯ ಚಿಹ್ನೆಗಳನ್ನು ಹೊಂದಿದೆ. "
            "ದಯವಿಟ್ಟು ಇಲ್ಲಿ ನಿಮ್ಮ ಒಟಿಪಿ, ಪಿನ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ನಮೂದಿಸಬೇಡಿ, ಸಂದೇಶವನ್ನು ಅಳಿಸಿ ಮತ್ತು ಅಗತ್ಯವಿದ್ದರೆ 1930 ಅಥವಾ ಚಕ್ಷು ಪೋರ್ಟಲ್‌ಗೆ ವರದಿ ಮಾಡಿ."
        ),
        "SAFE": (
            "ಈ ಲಿಂಕ್‌ನಲ್ಲಿ ತಕ್ಷಣದ ವಂಚನೆಯ ಲಕ್ಷಣಗಳು ಅಥವಾ ಅಪಾಯಕಾರಿ ಪಾವತಿ ಫಾರ್ಮ್‌ಗಳು ಕಂಡುಬಂದಿಲ್ಲ. "
            "ಆದರೂ, ನಿಮ್ಮ ಒಟಿಪಿ ಅಥವಾ ಪಿನ್ ಅನ್ನು ಯಾರಿಗೂ ನೀಡಬೇಡಿ ಮತ್ತು ಯಾವುದೇ ಬಿಲ್ ಅಥವಾ ಖಾತೆಯ ಮಾಹಿತಿಯನ್ನು ಅಧಿಕೃತ ಆ್ಯಪ್‌ನಲ್ಲಿಯೇ ಪರಿಶೀಲಿಸಿ."
        ),
        "APK_TRAP": (
            "ಎಚ್ಚರಿಕೆ! ಈ ಲಿಂಕ್ ಅಪಾಯಕಾರಿ ನಕಲಿ ಆ್ಯಪ್ ಅನ್ನು ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಒಟಿಪಿ ಕದಿಯಲು ಪ್ರಯತ್ನಿಸುತ್ತಿದೆ. "
            "ಯಾವುದೇ ಫೈಲ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ, ಈ ಸಂದೇಶವನ್ನು ತಕ್ಷಣ ಅಳಿಸಿ, ಮತ್ತು 1930 ಅಥವಾ ಚಕ್ಷು ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ದೂರು ನೀಡಿ."
        ),
    },
    "hi": {
        "DANGEROUS": (
            "यह लिंक खतरनाक लग रहा है और इसमें आपके पैसे या निजी जानकारी चुराने वाले धोखाधड़ी के साफ संकेत हैं। "
            "कृपया इस संदेश को तुरंत हटा दें, अपना ओटीपी या यूपीआई पिन कभी साझा न करें, और 1930 पर कॉल करके या चक्षु पोर्टल पर इसकी शिकायत करें।"
        ),
        "SUSPICIOUS": (
            "यह लिंक संदिग्ध लग रहा है और इसमें ऐसे चेतावनी संकेत हैं जो किसी असली सरकारी या बैंक सेवा से मेल नहीं खाते। "
            "कृपया यहाँ कोई ओटीपी, पिन या भुगतान विवरण न डालें, संदेश को हटा दें, और संदेह होने पर 1930 या चक्षु पोर्टल पर रिपोर्ट करें।"
        ),
        "SAFE": (
            "इस लिंक पर धोखाधड़ी के कोई स्पष्ट संकेत या संदिग्ध भुगतान फॉर्म नहीं मिले हैं। "
            "फिर भी, अपना ओटीपी या पिन कभी साझा न करें और किसी भी बिल या अलर्ट की जांच हमेशा आधिकारिक ऐप से ही करें।"
        ),
        "APK_TRAP": (
            "चेतावनी! यह लिंक एक खतरनाक नकली ऐप डाउनलोड करने की कोशिश कर रहा है जो आपके बैंक ओटीपी चुरा सकता है। "
            "कृपया कोई भी फाइल इंस्टॉल न करें, इस संदेश को तुरंत हटा दें, और 1930 या चक्षु पोर्टल पर शिकायत करें।"
        ),
    },
    "ta": {
        "DANGEROUS": "இந்த இணைப்பு ஆபத்தானது மற்றும் உங்கள் பணம் அல்லது தனிப்பட்ட விவரங்களைத் திருடும் மோசடி அறிகுறிகளைக் கொண்டுள்ளது. உடனடியாக இந்தச் செய்தியை அழிக்கவும், OTP அல்லது UPI PIN ஐப் பகிர வேண்டாம், 1930 அல்லது சக்ஷு போர்ட்டலில் புகார் செய்யவும்.",
        "SUSPICIOUS": "இந்த இணைப்பு சந்தேகத்திற்குரியதாக உள்ளது மற்றும் அதிகாரப்பூர்வ சேவையுடன் பொருந்தாத எச்சரிக்கை அறிகுறிகளைக் கொண்டுள்ளது. இங்கே OTP, PIN அல்லது கட்டண விவரங்களை உள்ளிட வேண்டாம்.",
        "SAFE": "இந்த இணைப்பில் வெளிப்படையான மோசடி பொறிகள் எதுவும் கண்டறியப்படவில்லை. இருப்பினும் உங்கள் OTP அல்லது PIN ஐ யாருடனும் பகிர வேண்டாம்.",
        "APK_TRAP": "எச்சரிக்கை! இந்த இணைப்பு உங்கள் வங்கி OTP களைத் திருடக்கூடிய ஆபத்தான போலி செயலியைப் பதிவிறக்க முயற்சிக்கிறது. எதையும் நிறுவ வேண்டாம், உடனடியாக 1930 இல் புகார் செய்யவும்.",
    },
    "te": {
        "DANGEROUS": "ఈ లింక్ ప్రమాదకరమైనది మరియు మీ డబ్బు లేదా వ్యక్తిగత వివరాలను దొంగిలించే మోసపూరిత సంకేతాలను చూపుతోంది. దయచేసి ఈ సందేశాన్ని వెంటనే తొలగించండి, OTP లేదా UPI PIN ఎప్పుడూ షేర్ చేయవద్దు, 1930 కు కాల్ చేయండి.",
        "SUSPICIOUS": "ఈ లింక్ అనుమానాస్పదంగా ఉంది. దయచేసి ఇక్కడ ఎటువంటి OTP, PIN లేదా చెల్లింపు వివరాలను నమోదు చేయవద్దు.",
        "SAFE": "ఈ లింక్‌లో స్పష్టమైన మోసపూరిత సంకేతాలు కనిపించలేదు. అయినప్పటికీ, మీ OTP లేదా PIN ను ఎవరితోనూ పంచుకోవద్దు.",
        "APK_TRAP": "హెచ్చరిక! ఈ లింక్ మీ బ్యాంక్ OTP లను దొంగిలించడానికి ప్రమాదకరమైన నకిలీ యాప్‌ను డౌన్‌లోడ్ చేయడానికి ప్రయత్నిస్తోంది. ఏదీ ఇన్‌స్టాల్ చేయవద్దు, వెంటనే 1930 కు ఫిర్యాదు చేయండి.",
    },
    "ml": {
        "DANGEROUS": "ഈ ലിങ്ക് അപകടകരമാണ്, നിങ്ങളുടെ പണമോ വ്യക്തിഗത വിവരങ്ങളോ മോഷ്ടിക്കാനുള്ള തട്ടിപ്പിന്റെ ലക്ഷണങ്ങൾ കാണിക്കുന്നു. ദയവായി ഈ സന്ദേശം ഉടൻ ഇല്ലാതാക്കുക, OTP അല്ലെങ്കിൽ UPI PIN പങ്കിടരുത്, 1930-ൽ വിളിക്കുക.",
        "SUSPICIOUS": "ഈ ലിങ്ക് സംശയാസ്പദമാണ്. ദയവായി ഇവിടെ OTP, PIN അല്ലെങ്കിൽ പേയ്‌മെന്റ് വിവരങ്ങൾ നൽകരുത്.",
        "SAFE": "ഈ ലിങ്കിൽ വ്യക്തമായ തട്ടിപ്പ് ലക്ഷണങ്ങളൊന്നും കണ്ടെത്തിയില്ല. എന്നിരുന്നാലും, നിങ്ങളുടെ OTP അല്ലെങ്കിൽ PIN ആരുമായും പങ്കിടരുത്.",
        "APK_TRAP": "മുന്നറിയിപ്പ്! നിങ്ങളുടെ ബാങ്ക് OTP-കൾ മോഷ്ടിക്കാൻ ഈ ലിങ്ക് അപകടകരമായ ഒരു വ്യാജ ആപ്പ് ഡൗൺലോഡ് ചെയ്യാൻ ശ്രമിക്കുന്നു. ഒന്നും ഇൻസ്റ്റാൾ ചെയ്യരുത്, 1930-ൽ റിപ്പോർട്ട് ചെയ്യുക.",
    },
    "mr": {
        "DANGEROUS": "ही लिंक धोकादायक आहे आणि तुमचे पैसे किंवा वैयक्तिक माहिती चोरण्याचा प्रयत्न करणारी फसवणुकीची लक्षणे दाखवत आहे. कृपया हा संदेश लगेच हटवा, OTP किंवा UPI PIN शेअर करू नका आणि 1930 वर तक्रार करा.",
        "SUSPICIOUS": "ही लिंक संशयास्पद आहे. कृपया येथे कोणताही OTP, PIN किंवा पेमेंट तपशील टाकू नका.",
        "SAFE": "या लिंकवर फसवणुकीची कोणतीही स्पष्ट लक्षणे आढळली नाहीत. तरीही, तुमचा OTP किंवा PIN कोणाशीही शेअर करू नका.",
        "APK_TRAP": "सावधान! ही लिंक तुमचे बँक OTP चोरण्यासाठी धोकादायक बनावट अ‍ॅप डाउनलोड करण्याचा प्रयत्न करत आहे. काहीही इन्स्टॉल करू नका आणि 1930 वर तक्रार करा.",
    },
    "bn": {
        "DANGEROUS": "এই লিঙ্কটি বিপজ্জনক এবং আপনার টাকা বা ব্যক্তিগত তথ্য চুরি করার প্রতারণার স্পষ্ট লক্ষণ দেখাচ্ছে। অনুগ্রহ করে এখনই বার্তাটি মুছে ফেলুন, কখনোই OTP বা UPI PIN শেয়ার করবেন না এবং 1930 নম্বরে অভিযোগ জানান।",
        "SUSPICIOUS": "এই লিঙ্কটি সন্দেহজনক। অনুগ্রহ করে এখানে কোনো OTP, PIN বা পেমেন্টের তথ্য দেবেন না।",
        "SAFE": "এই লিঙ্কে কোনো স্পষ্ট প্রতারণার ফাঁদ পাওয়া যায়নি। তবুও, কখনোই আপনার OTP বা PIN কারো সাথে শেয়ার করবেন না।",
        "APK_TRAP": "সতর্কতা! এই লিঙ্কটি আপনার ব্যাঙ্ক OTP চুরি করার জন্য একটি বিপজ্জনক ভুয়া অ্যাপ ডাউনলোড করার চেষ্টা করছে। কিছু ইনস্টল করবেন না এবং 1930 নম্বরে রিপোর্ট করুন।",
    },
    "gu": {
        "DANGEROUS": "આ લિંક જોખમી છે અને તમારા પૈસા અથવા અંગત વિગતો ચોરવાના છેતરપિંડીના સંકેતો બતાવે છે. કૃપા કરીને આ સંદેશ તરત જ ડિલીટ કરો, OTP અથવા UPI PIN શેર કરશો નહીં અને 1930 પર ફરિયાદ કરો.",
        "SUSPICIOUS": "આ લિંક શંકાસ્પદ છે. કૃપા કરીને અહીં કોઈ OTP, PIN અથવા ચુકવણીની વિગતો દાખલ કરશો નહીં.",
        "SAFE": "આ લિંક પર છેતરપિંડીના કોઈ સ્પષ્ટ સંકેતો મળ્યા નથી. તેમ છતાં, તમારો OTP અથવા PIN ક્યારેય શેર કરશો નહીં.",
        "APK_TRAP": "ચેતવણી! આ લિંક તમારા બેંક OTP ચોરવા માટે જોખમી નકલી એપ ડાઉનલોડ કરવાનો પ્રયાસ કરી રહી છે. કંઈપણ ઇન્સ્ટોલ કરશો નહીં અને 1930 પર જાણ કરો.",
    },
    "pa": {
        "DANGEROUS": "ਇਹ ਲਿੰਕ ਖਤਰਨਾਕ ਹੈ ਅਤੇ ਤੁਹਾਡੇ ਪੈਸੇ ਜਾਂ ਨਿੱਜੀ ਜਾਣਕਾਰੀ ਚੋਰੀ ਕਰਨ ਵਾਲੀ ਧੋਖਾਧੜੀ ਦੇ ਸੰਕੇਤ ਦਿਖਾ ਰਿਹਾ ਹੈ। ਕਿਰਪਾ ਕਰਕੇ ਇਸ ਸੁਨੇਹੇ ਨੂੰ ਤੁਰੰਤ ਮਿਟਾਓ, ਆਪਣਾ OTP ਜਾਂ UPI PIN ਕਦੇ ਸਾਂਝਾ ਨਾ ਕਰੋ ਅਤੇ 1930 'ਤੇ ਸ਼ਿਕਾਇਤ ਕਰੋ।",
        "SUSPICIOUS": "ਇਹ ਲਿੰਕ ਸ਼ੱਕੀ ਹੈ। ਕਿਰਪਾ ਕਰਕੇ ਇੱਥੇ ਕੋਈ OTP, PIN ਜਾਂ ਭੁਗਤਾਨ ਵੇਰਵੇ ਦਰਜ ਨਾ ਕਰੋ।",
        "SAFE": "ਇਸ ਲਿੰਕ 'ਤੇ ਧੋਖਾਧੜੀ ਦੇ ਕੋਈ ਸਪੱਸ਼ਟ ਸੰਕੇਤ ਨਹੀਂ ਮਿਲੇ ਹਨ। ਫਿਰ ਵੀ, ਆਪਣਾ OTP ਜਾਂ PIN ਕਦੇ ਵੀ ਕਿਸੇ ਨਾਲ ਸਾਂਝਾ ਨਾ ਕਰੋ।",
        "APK_TRAP": "ਚੇਤਾਵਨੀ! ਇਹ ਲਿੰਕ ਤੁਹਾਡੇ ਬੈਂਕ OTP ਚੋਰੀ ਕਰਨ ਲਈ ਇੱਕ ਖਤਰਨਾਕ ਨਕਲੀ ਐਪ ਡਾਊਨਲੋਡ ਕਰਨ ਦੀ ਕੋਸ਼ਿਸ਼ ਕਰ ਰਿਹਾ ਹੈ। ਕੁਝ ਵੀ ਇੰਸਟਾਲ ਨਾ ਕਰੋ ਅਤੇ 1930 'ਤੇ ਰਿਪੋਰਟ ਕਰੋ।",
    },
    "es": {
        "DANGEROUS": "Este enlace parece peligroso y muestra señales claras de estafa para robar su dinero o datos personales. Elimine este mensaje ahora, nunca comparta su OTP o PIN y repórtelo.",
        "SUSPICIOUS": "Este enlace parece sospechoso. No ingrese códigos OTP, PIN ni datos de pago aquí.",
        "SAFE": "No detectamos trampas obvias de estafa en este enlace. Aun así, nunca comparta su OTP o PIN.",
        "APK_TRAP": "Advertencia. Este enlace intenta descargar una aplicación falsa peligrosa para robar sus códigos bancarios. No instale nada.",
    },
    "fr": {
        "DANGEROUS": "Ce lien semble dangereux et présente des signes d'arnaque visant à voler votre argent ou vos données. Supprimez ce message immédiatement et ne partagez jamais votre code OTP ou PIN.",
        "SUSPICIOUS": "Ce lien semble suspect. N'entrez aucun code OTP, PIN ou détail de paiement ici.",
        "SAFE": "Aucun piège évident n'a été détecté sur ce lien. Néanmoins, ne partagez jamais votre code OTP ou PIN.",
        "APK_TRAP": "Attention. Ce lien tente de télécharger une fausse application dangereuse pour voler vos codes bancaires. N'installez rien.",
    },
    "de": {
        "DANGEROUS": "Dieser Link wirkt gefährlich und zeigt klare Anzeichen eines Betrugs. Löschen Sie diese Nachricht sofort und geben Sie niemals Ihre OTP oder PIN weiter.",
        "SUSPICIOUS": "Dieser Link wirkt verdächtig. Geben Sie hier keine OTP, PIN oder Zahlungsdaten ein.",
        "SAFE": "Auf diesem Link wurden keine offensichtlichen Betrugsfallen gefunden. Teilen Sie dennoch niemals Ihre OTP oder PIN.",
        "APK_TRAP": "Warnung. Dieser Link versucht, eine gefährliche gefälschte App herunterzuladen. Installieren Sie nichts.",
    },
    "ar": {
        "DANGEROUS": "يبدو هذا الرابط خطيرًا ويظهر علامات واضحة للاحتيال لسرقة أموالك أو بياناتك الشخصية. يرجى حذف هذه الرسالة فورًا وعدم مشاركة رمز التحقق أو الرقم السري.",
        "SUSPICIOUS": "يبدو هذا الرابط مشبوهًا. لا تدخل أي رمز تحقق أو بيانات دفع هنا.",
        "SAFE": "لم نجد علامات احتيال واضحة في هذا الرابط. ومع ذلك، لا تشارك رمز التحقق أو الرقم السري مع أي شخص.",
        "APK_TRAP": "تحذير. يحاول هذا الرابط تنزيل تطبيق مزيف خطير لسرقة رموز البنك الخاصة بك. لا تقم بتثبيت أي شيء.",
    },
    "ja": {
        "DANGEROUS": "このリンクは危険であり、金銭や個人情報を盗もうとする詐欺の明確な兆候があります。直ちにこのメッセージを削除し、OTPや暗証番号を決して共有しないでください。",
        "SUSPICIOUS": "このリンクは不審です。OTP、暗証番号、または支払い情報をここに入力しないでください。",
        "SAFE": "このリンクに明らかな詐欺の罠は見つかりませんでした。それでも、OTPや暗証番号は絶対に共有しないでください。",
        "APK_TRAP": "警告。このリンクは銀行のOTPを盗む危険な偽アプリをダウンロードしようとしています。何もインストールしないでください。",
    },
    "ko": {
        "DANGEROUS": "이 링크는 위험하며 돈이나 개인정보를 훔치려는 사기 징후가 분명합니다. 즉시 이 메시지를 삭제하고 OTP나 비밀번호를 절대 공유하지 마세요.",
        "SUSPICIOUS": "이 링크는 의심스럽습니다. 여기에 OTP, PIN 또는 결제 정보를 입력하지 마세요.",
        "SAFE": "이 링크에서 명백한 사기 함정은 발견되지 않았습니다. 그래도 OTP나 PIN은 절대 공유하지 마세요.",
        "APK_TRAP": "경고. 이 링크는 은행 OTP를 훔치기 위해 위험한 가짜 앱을 다운로드하려고 합니다. 아무것도 설치하지 마세요.",
    },
    "pt": {
        "DANGEROUS": "Este link parece perigoso e mostra sinais claros de golpe para roubar seu dinheiro ou dados. Exclua esta mensagem agora e nunca compartilhe seu OTP ou PIN.",
        "SUSPICIOUS": "Este link parece suspeito. Não insira nenhum OTP, PIN ou dados de pagamento aqui.",
        "SAFE": "Não encontramos armadilhas óbvias de golpe neste link. Mesmo assim, nunca compartilhe seu OTP ou PIN.",
        "APK_TRAP": "Aviso. Este link tenta baixar um aplicativo falso perigoso para roubar seus códigos bancários. Não instale nada.",
    },
    "id": {
        "DANGEROUS": "Tautan ini terlihat berbahaya dan menunjukkan tanda penipuan untuk mencuri uang atau data pribadi Anda. Segera hapus pesan ini dan jangan pernah bagikan OTP atau PIN Anda.",
        "SUSPICIOUS": "Tautan ini terlihat mencurigakan. Jangan masukkan OTP, PIN, atau detail pembayaran di sini.",
        "SAFE": "Kami tidak menemukan jebakan penipuan yang jelas pada tautan ini. Meski begitu, jangan pernah bagikan OTP atau PIN Anda.",
        "APK_TRAP": "Peringatan. Tautan ini mencoba mengunduh aplikasi palsu berbahaya untuk mencuri OTP bank Anda. Jangan instal apa pun.",
    },
    "vi": {
        "DANGEROUS": "Liên kết này có vẻ nguy hiểm và có dấu hiệu lừa đảo nhằm đánh cắp tiền hoặc thông tin cá nhân của bạn. Vui lòng xóa tin nhắn này ngay và không bao giờ chia sẻ mã OTP hoặc mã PIN.",
        "SUSPICIOUS": "Liên kết này có vẻ đáng ngờ. Không nhập mã OTP, mã PIN hoặc thông tin thanh toán tại đây.",
        "SAFE": "Chúng tôi không phát hiện dấu hiệu lừa đảo rõ ràng trên liên kết này. Tuy nhiên, không bao giờ chia sẻ mã OTP hoặc mã PIN của bạn.",
        "APK_TRAP": "Cảnh báo. Liên kết này đang cố tải xuống một ứng dụng giả mạo nguy hiểm để đánh cắp mã OTP ngân hàng. Không cài đặt bất kỳ thứ gì.",
    },
    "tr": {
        "DANGEROUS": "Bu bağlantı tehlikeli görünüyor ve paranızı veya kişisel bilgilerinizi çalmaya yönelik dolandırıcılık belirtileri gösteriyor. Bu mesajı hemen silin ve OTP veya PIN kodunuzu asla paylaşmayın.",
        "SUSPICIOUS": "Bu bağlantı şüpheli görünüyor. Buraya herhangi bir OTP, PIN veya ödeme bilgisi girmeyin.",
        "SAFE": "Bu bağlantıda bariz bir dolandırıcılık tuzağı bulamadık. Yine de OTP veya PIN kodunuzu asla kimseyle paylaşmayın.",
        "APK_TRAP": "Uyarı. Bu bağlantı banka OTP kodlarınızı çalmak için tehlikeli bir sahte uygulama indirmeye çalışıyor. Hiçbir şey yüklemeyin.",
    },
    "ru": {
        "DANGEROUS": "Эта ссылка выглядит опасной и содержит явные признаки мошенничества. Немедленно удалите это сообщение и никогда не сообщайте свой одноразовый код или ПИН-код.",
        "SUSPICIOUS": "Эта ссылка выглядит подозрительно. Не вводите здесь одноразовые коды, ПИН-коды или платежные данные.",
        "SAFE": "На этой ссылке не обнаружено явных признаков мошенничества. Тем не менее никогда не передавайте свои коды подтверждения другим лицам.",
        "APK_TRAP": "Внимание. Эта ссылка пытается загрузить опасное поддельное приложение для кражи банковских кодов. Ничего не устанавливайте.",
    },
    "it": {
        "DANGEROUS": "Questo link sembra pericoloso e mostra chiari segni di truffa per rubare denaro o dati personali. Elimina subito questo messaggio e non condividere mai OTP o PIN.",
        "SUSPICIOUS": "Questo link sembra sospetto. Non inserire qui codici OTP, PIN o dati di pagamento.",
        "SAFE": "Non abbiamo rilevato trappole evidenti in questo link. Tuttavia, non condividere mai il tuo OTP o PIN.",
        "APK_TRAP": "Attenzione. Questo link tenta di scaricare una falsa app pericolosa per rubare i tuoi codici bancari. Non installare nulla.",
    },
    "nl": {
        "DANGEROUS": "Deze link lijkt gevaarlijk en vertoont duidelijke tekenen van oplichting. Verwijder dit bericht direct en deel nooit uw OTP of pincode.",
        "SUSPICIOUS": "Deze link lijkt verdacht. Voer hier geen OTP, pincode of betaalgegevens in.",
        "SAFE": "We hebben geen duidelijke oplichtingstrucs op deze link gevonden. Deel desondanks nooit uw OTP of pincode.",
        "APK_TRAP": "Waarschuwing. Deze link probeert een gevaarlijke nep-app te downloaden om uw bankcodes te stelen. Installeer niets.",
    },
    "pl": {
        "DANGEROUS": "Ten link wygląda na niebezpieczny i wykazuje wyraźne oznaki oszustwa. Natychmiast usuń tę wiadomość i nigdy nie udostępniaj kodu OTP ani PIN.",
        "SUSPICIOUS": "Ten link wygląda podejrzanie. Nie wpisuj tutaj kodu OTP, PIN ani danych płatności.",
        "SAFE": "Nie znaleźliśmy oczywistych pułapek na tym linku. Mimo to nigdy nie udostępniaj nikomu swojego kodu OTP ani PIN.",
        "APK_TRAP": "Ostrzeżenie. Ten link próbuje pobrać niebezpieczną fałszywą aplikację. Niczego nie instaluj.",
    },
    "ur": {
        "DANGEROUS": "یہ لنک خطرناک لگتا ہے اور آپ کے پیسے یا ذاتی معلومات چرانے کے واضح آثار دکھا رہا ہے۔ براہ کرم اس پیغام کو فوراً حذف کریں، اپنا OTP یا PIN کبھی شیئر نہ کریں اور 1930 پر شکایت کریں۔",
        "SUSPICIOUS": "یہ لنک مشکوک لگتا ہے۔ براہ کرم یہاں کوئی OTP، PIN یا ادائیگی کی تفصیلات درج نہ کریں۔",
        "SAFE": "اس لنک میں دھوکہ دہی کے کوئی واضح آثار نہیں ملے۔ تاہم، اپنا OTP یا PIN کسی کے ساتھ شیئر نہ کریں۔",
        "APK_TRAP": "انتباہ۔ یہ لنک آپ کے بینک OTP چرانے کے لیے ایک خطرناک جعلی ایپ ڈاؤن لوڈ کرنے کی کوشش کر رہا ہے۔ کچھ بھی انسٹال نہ کریں۔",
    },
}

_EMERGENCY_SCRIPTS: dict[str, dict[str, str]] = {
    "en": {
        "credentials_entered": (
            "Stay calm, you can still protect your money if you act right now. "
            "First, call 1930 immediately to freeze any fraudulent transfer. "
            "Second, call your bank's official helpline to block your UPI, debit card, and net banking. "
            "Finally, turn off mobile data if you installed any unknown app."
        ),
        "clicked_only": (
            "Take a deep breath. If you only opened the link and did not enter your OTP, PIN, or install an app, your bank account is usually safe. "
            "Close the browser tab right away, delete the message, and block the sender."
        ),
    },
    "kn": {
        "credentials_entered": (
            "ಗಾಬರಿಯಾಗಬೇಡಿ, ಈಗಲೇ ಕ್ರಮ ಕೈಗೊಂಡರೆ ನಿಮ್ಮ ಹಣವನ್ನು ಉಳಿಸಬಹುದು. "
            "ಮೊದಲು ತಕ್ಷಣ 1930 ಗೆ ಕರೆ ಮಾಡಿ ವಹಿವಾಟನ್ನು ತಡೆಹಿಡಿಯಿರಿ. "
            "ನಂತರ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಸಹಾಯವಾಣಿಗೆ ಕರೆ ಮಾಡಿ ಯುಪಿಐ, ಕಾರ್ಡ್ ಮತ್ತು ನೆಟ್ ಬ್ಯಾಂಕಿಂಗ್ ಬ್ಲಾಕ್ ಮಾಡಿಸಿ. "
            "ಯಾವುದೇ ಅಪರಿಚಿತ ಆ್ಯಪ್ ಡೌನ್‌ಲೋಡ್ ಆಗಿದ್ದರೆ ತಕ್ಷಣ ಮೊಬೈಲ್ ಡೇಟಾ ಆಫ್ ಮಾಡಿ."
        ),
        "clicked_only": (
            "ಗಾಬರಿಯಾಗಬೇಡಿ. ನೀವು ಕೇವಲ ಲಿಂಕ್ ತೆರೆದಿದ್ದು, ಯಾವುದೇ ಒಟಿಪಿ, ಪಿನ್ ನಮೂದಿಸದಿದ್ದರೆ ಅಥವಾ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡದಿದ್ದರೆ ನಿಮ್ಮ ಖಾತೆ ಸುರಕ್ಷಿತವಾಗಿರುತ್ತದೆ. "
            "ತಕ್ಷಣ ಬ್ರೌಸರ್ ಟ್ಯಾಬ್ ಮುಚ್ಚಿ, ಸಂದೇಶವನ್ನು ಅಳಿಸಿ ಮತ್ತು ಆ ನಂಬರ್ ಬ್ಲಾಕ್ ಮಾಡಿ."
        ),
    },
    "hi": {
        "credentials_entered": (
            "घबराएं नहीं, अभी तुरंत कदम उठाने से आपका पैसा बचाया जा सकता है। "
            "सबसे पहले तुरंत 1930 पर कॉल करें ताकि धोखाधड़ी वाला लेनदेन रोका जा सके। "
            "इसके बाद अपने बैंक की आधिकारिक हेल्पलाइन पर कॉल करके यूपीआई, कार्ड और नेट बैंकिंग ब्लॉक करवाएं। "
            "अगर कोई अनजान ऐप डाउनलोड हुआ है तो तुरंत मोबाइल डेटा बंद कर दें।"
        ),
        "clicked_only": (
            "चिंता न करें। अगर आपने सिर्फ लिंक खोला है और कोई ओटीपी, पिन नहीं डाला या ऐप इंस्टॉल नहीं किया, तो आपका खाता सुरक्षित है। "
            "तुरंत ब्राउज़र बंद करें, संदेश हटा दें और उस नंबर को ब्लॉक कर दें।"
        ),
    },
}


def get_emergency_script(language: str, entered_credentials: bool) -> str:
    lang_code = language if language in _EMERGENCY_SCRIPTS else "en"
    key = "credentials_entered" if entered_credentials else "clicked_only"
    return _EMERGENCY_SCRIPTS[lang_code][key]


def _format_plain_fields(detected_forms: list[str]) -> str:
    labels = [_FIELD_PLAIN_LABELS.get(field, field) for field in detected_forms]
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return ", ".join(labels[:-1]) + f", and {labels[-1]}"


def _assign_status(risk_score: int) -> str:
    if risk_score >= 60:
        return "DANGEROUS"
    if risk_score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def build_verdict(
    message: str,
    sandbox_data: dict[str, Any],
    intel_data: dict[str, Any],
    vision_data: dict[str, Any] | None = None,
    language: str = "en",
) -> dict[str, Any]:
    """Compute transparent risk score, status, plain-language evidence, and spoken script."""
    redirect_chain: list[str] = sandbox_data.get("redirect_chain") or []
    detected_forms: list[str] = sandbox_data.get("detected_forms") or []
    urgency_flags: list[str] = sandbox_data.get("urgency_flags") or []
    sandbox_error: str | None = sandbox_data.get("error")
    ssrf_blocked: bool = bool(sandbox_data.get("ssrf_blocked"))
    apk_trap: dict[str, Any] = sandbox_data.get("apk_trap") or {}

    domain_age_days: int | None = intel_data.get("domain_age_days")
    vt_data: dict[str, Any] = intel_data.get("virustotal") or {}
    vt_malicious = int(vt_data.get("malicious", 0) or 0)
    vt_suspicious = int(vt_data.get("suspicious", 0) or 0)
    tls_info: dict[str, Any] = intel_data.get("tls") or {}
    url_heuristics: dict[str, Any] = intel_data.get("url_heuristics") or {}
    heuristic_points = int(url_heuristics.get("risk_points", 0) or 0)

    score = 0
    breakdown: list[dict[str, Any]] = []

    if ssrf_blocked:
        score = 95
        breakdown.append({"rule": "SSRF Guard blocked internal/unsafe URI target", "points": 95})
    else:
        if apk_trap.get("detected"):
            score += 75
            breakdown.append(
                {"rule": f"CRITICAL: Drive-by malware/APK trap ({apk_trap.get('filename', 'file')})", "points": 75}
            )

        if len(redirect_chain) > 1:
            score += 20
            breakdown.append({"rule": "Multiple redirects detected (> 1 hop)", "points": 20})

        if detected_forms:
            score += 35
            breakdown.append({"rule": "Sensitive credential/payment inputs requested", "points": 35})

        if len(urgency_flags) >= 2:
            score += 20
            breakdown.append({"rule": "Multiple urgency/fear keywords on landing page", "points": 20})
        elif len(urgency_flags) == 1:
            score += 15
            breakdown.append({"rule": "Urgency keyword detected on landing page", "points": 15})
        elif sandbox_error and any(
            kw in message.lower()
            for kw in ("blocked", "suspended", "kyc", "disconnected", "urgent", "pay now")
        ):
            score += 15
            breakdown.append({"rule": "Urgency wording in message (page unreachable)", "points": 15})

        if domain_age_days is not None and domain_age_days < 30:
            score += 20
            breakdown.append({"rule": "Newly created domain (< 30 days old)", "points": 20})

        if heuristic_points > 0:
            score += heuristic_points
            breakdown.append({"rule": "Suspicious URL lexical/homograph pattern", "points": heuristic_points})

        if tls_info.get("checked") and not tls_info.get("valid"):
            score += 15
            breakdown.append({"rule": f"TLS certificate anomaly ({tls_info.get('note', 'invalid')})", "points": 15})

        if vt_malicious > 0:
            score += 30
            breakdown.append({"rule": f"VirusTotal malicious detections ({vt_malicious})", "points": 30})
        elif vt_suspicious > 0:
            score += 15
            breakdown.append({"rule": f"VirusTotal suspicious detections ({vt_suspicious})", "points": 15})

        if vision_data and vision_data.get("impersonated_brand"):
            score += 15
            breakdown.append(
                {"rule": f"Visual brand impersonation ({vision_data['impersonated_brand']})", "points": 15}
            )

    risk_score = min(100, score)
    status = _assign_status(risk_score)

    evidence: list[str] = []

    if ssrf_blocked:
        evidence.append(sandbox_error or "Blocked by SSRF Guard: unsafe or private network address.")
    elif apk_trap.get("detected"):
        evidence.append(apk_trap.get("warning", "Attempted drive-by APK/malware download was blocked safely."))
    else:
        if len(redirect_chain) > 1:
            evidence.append(
                "This link bounced through another hidden web address before opening, a common trick used to disguise scam sites."
            )
        elif not sandbox_error:
            evidence.append(
                "This link went straight to its destination without bouncing through hidden redirects."
            )

        if detected_forms:
            fields_text = _format_plain_fields(detected_forms)
            evidence.append(
                f"The page asks for sensitive details ({fields_text}). Trusted banks, utility boards, and government offices do not ask for these through message links."
            )
        elif not sandbox_error:
            evidence.append(
                "The page did not ask you to type any passwords, OTPs, PINs, or payment card details."
            )

        if urgency_flags:
            evidence.append(
                "The page uses urgent warnings and threats (such as blocking or disconnecting your service) to rush you into acting quickly."
            )
        elif sandbox_error:
            evidence.append(
                "The website could not be reached right now, which often happens when short-lived scam pages are taken down or broken."
            )
        else:
            evidence.append(
                "No scare tactics or urgent payment threats were found on the page."
            )

        heuristic_flags = url_heuristics.get("flags") or []
        if vt_malicious > 0 or vt_suspicious > 0:
            evidence.append("Independent security scanners have already flagged this web address as unsafe.")
        elif heuristic_flags:
            evidence.append(heuristic_flags[0] + ".")
        elif domain_age_days is not None and domain_age_days < 30:
            evidence.append(
                f"This website address appears brand new ({domain_age_days} days old), which is a classic warning sign of a temporary scam page."
            )
        elif domain_age_days is not None:
            evidence.append(
                f"This website address has existed for {domain_age_days} days and had no security scanner warnings."
            )

    lang_code = language if language in _SPOKEN_SCRIPTS else "en"
    script_key = "APK_TRAP" if apk_trap.get("detected") else status
    voice_script = _SPOKEN_SCRIPTS[lang_code][script_key]

    return {
        "risk_score": risk_score,
        "status": status,
        "evidence": evidence[:4],
        "score_breakdown": breakdown,
        "voice_script": voice_script,
        "language": lang_code,
    }


def build_cybercrime_report(
    redacted_message: str,
    extracted_url: str,
    sandbox_data: dict[str, Any],
    intel_data: dict[str, Any],
    vision_data: dict[str, Any],
    verdict_data: dict[str, Any],
) -> dict[str, str]:
    """Generate a ready-to-file 1930 / Chakshu complaint and a WhatsApp Family Safety Alert."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    defanged_initial = defang_url(extracted_url)
    defanged_final = defang_url(sandbox_data.get("final_url") or extracted_url)
    network = intel_data.get("network") or {}
    resolved_ip = network.get("ip") or (sandbox_data.get("ssrf_check") or {}).get("resolved_ip") or "Unresolved"
    asn = network.get("asn") or "N/A"
    spoofed = vision_data.get("impersonated_brand") or "Unverified / Unknown Sender"
    sha256_hash = sandbox_data.get("screenshot_sha256") or "N/A (No screenshot captured)"
    apk_trap = sandbox_data.get("apk_trap") or {}

    threat_type = (
        f"Malicious APK / Drive-By Malware ({apk_trap.get('filename')})"
        if apk_trap.get("detected")
        else f"Phishing / Social Engineering ({verdict_data['status']}, Score {verdict_data['risk_score']}/100)"
    )

    complaint_text = (
        "OFFICIAL CYBERCRIME INCIDENT REPORT (1930 / CHAKSHU - SANCHAR SAATHI)\n"
        f"Timestamp: {timestamp}\n"
        f"Threat Classification: {threat_type}\n"
        f"Suspect URL (Defanged): {defanged_initial}\n"
        f"Final Landing URL (Defanged): {defanged_final}\n"
        f"Resolved Host / ASN: {resolved_ip} ({asn})\n"
        f"Spoofed Identity: {spoofed}\n"
        f"Victim Message (PII Redacted): \"{redacted_message}\"\n"
        f"Forensic Screenshot SHA-256: {sha256_hash}\n"
        "Generated by: Scam SOC Crew (Sandboxed Browser Triage)"
    )

    brand_label = vision_data.get("impersonated_brand") or "suspicious"
    whatsapp_alert = (
        f"⚠️ Family Safety Alert: Fake {brand_label} scam link detected! "
        f"Verified as {verdict_data['status']} ({verdict_data['risk_score']}/100) by Scam SOC Crew. "
        "Do NOT click this link, do NOT install any APK, and NEVER share your OTP or UPI PIN. "
        "If targeted, report on Chakshu (sancharsaathi.gov.in) or call 1930."
    )

    return {
        "complaint_text": complaint_text,
        "whatsapp_alert": whatsapp_alert,
        "defanged_url": defanged_final,
    }


SARVAM_TTS_ENDPOINT = "https://api.sarvam.ai/text-to-speech"
SARVAM_LANG_MAP: dict[str, str] = {
    "en": "en-IN",
    "hi": "hi-IN",
    "kn": "kn-IN",
    "ta": "ta-IN",
    "te": "te-IN",
    "ml": "ml-IN",
    "mr": "mr-IN",
    "bn": "bn-IN",
    "gu": "gu-IN",
    "pa": "pa-IN",
}


async def _generate_sarvam_tts_async(script_text: str, language: str) -> str | None:
    """Synthesize spoken audio via Sarvam AI Bulbul TTS as base64 WAV."""
    api_key = os.getenv("SARVAM_API_KEY", "").strip()
    target_lang = SARVAM_LANG_MAP.get(language)
    if not api_key or not target_lang or not script_text.strip():
        return None

    cache_key = hashlib.sha256(f"sarvam:{target_lang}:{script_text}".encode("utf-8")).hexdigest()
    now = time.monotonic()
    cached = _AUDIO_CACHE.get(cache_key)
    if cached and cached[0] > now:
        return cached[1]

    headers = {
        "api-subscription-key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "inputs": [script_text[:500]],
        "target_language_code": target_lang,
        "speaker": os.getenv("SARVAM_SPEAKER", "anushka").strip() or "anushka",
        "model": os.getenv("SARVAM_MODEL", "bulbul:v2").strip() or "bulbul:v2",
        "enable_preprocessing": True,
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                SARVAM_TTS_ENDPOINT,
                headers=headers,
                json=payload,
                timeout=ELEVENLABS_TIMEOUT_SECONDS,
            )
        if resp.status_code != 200:
            logger.warning("Sarvam TTS HTTP %s: %s", resp.status_code, resp.text[:200])
            return None
        audios = resp.json().get("audios") or []
        if not audios:
            return None
        b64 = audios[0]
        _AUDIO_CACHE[cache_key] = (now + AUDIO_CACHE_TTL_SECONDS, b64)
        return b64
    except Exception as exc:  # noqa: BLE001
        logger.warning("Sarvam TTS request failed: %s", exc)
        return None


async def generate_voice_audio_async(script_text: str, language: str = "en") -> str | None:
    """Synthesize spoken audio asynchronously via Sarvam AI (preferred) or ElevenLabs."""
    sarvam_audio = await _generate_sarvam_tts_async(script_text, language)
    if sarvam_audio:
        return sarvam_audio

    api_key = os.getenv("ELEVENLABS_API_KEY", "").strip()
    if not api_key or not script_text.strip():
        return None

    lang = language if language in SUPPORTED_LANGUAGE_NAMES else "en"
    voice_id = os.getenv("ELEVENLABS_VOICE_ID", ELEVENLABS_DEFAULT_VOICE_ID).strip() or ELEVENLABS_DEFAULT_VOICE_ID
    model_id = os.getenv("ELEVENLABS_MODEL_ID", ELEVENLABS_DEFAULT_MODEL_ID).strip() or ELEVENLABS_DEFAULT_MODEL_ID

    cache_key = hashlib.sha256(f"{voice_id}:{model_id}:{lang}:{script_text}".encode("utf-8")).hexdigest()
    now = time.monotonic()
    cached = _AUDIO_CACHE.get(cache_key)
    if cached and cached[0] > now:
        return cached[1]

    endpoint = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
    headers = {
        "xi-api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "audio/mpeg",
    }
    payload = {
        "text": script_text,
        "model_id": model_id,
        "language_code": lang,
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=ELEVENLABS_TIMEOUT_SECONDS,
            )
        if resp.status_code != 200 or not resp.content:
            logger.warning("ElevenLabs HTTP %s: %s", resp.status_code, resp.text[:200])
            return None
        b64 = base64.b64encode(resp.content).decode("utf-8")
        _AUDIO_CACHE[cache_key] = (now + AUDIO_CACHE_TTL_SECONDS, b64)
        return b64
    except httpx.HTTPError as exc:
        logger.warning("ElevenLabs request failed: %s", exc)
        return None


def generate_voice_audio(script_text: str, language: str = "en") -> str | None:
    """Synchronous wrapper for generate_voice_audio_async."""
    return asyncio.run(generate_voice_audio_async(script_text, language))
