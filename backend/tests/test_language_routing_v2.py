"""Language path fixtures only; not phishing accuracy or training examples."""
import pytest
from backend.language_routing_v2 import route_email_language, language_windows, prepare_language_text
from backend.ml_runtime import _classify_language

ENGLISH = "Please review the attached agenda for our project meeting tomorrow. We will discuss progress and plan the next stage together."
SPANISH = "Su cuenta requiere una verificación urgente. Confirme su contraseña para evitar la suspensión y revise los detalles de seguridad inmediatamente."
UNSUPPORTED = [
    ("fr", "Veuillez trouver le compte rendu de notre réunion. Nous allons discuter des prochains travaux et organiser les projets de notre équipe."),
    ("de", "Bitte lesen Sie den Bericht über unser letztes Treffen. Wir werden morgen die nächsten Schritte für unser gemeinsames Projekt besprechen."),
    ("ru", "Пожалуйста, прочитайте отчет о нашей последней встрече. Завтра мы обсудим следующие шаги совместного проекта и рабочий график команды."),
    ("ar", "يرجى مراجعة جدول أعمال اجتماع المشروع غدًا. سنناقش التقدم المحرز ونخطط للمرحلة التالية معًا خلال اجتماع فريق العمل."),
]


@pytest.mark.parametrize('text,language',[(ENGLISH,'en'),(SPANISH,'es'),*[(text,lang) for lang,text in UNSUPPORTED]])
def test_actual_identifier_keeps_all_languages(text,language):
    result=route_email_language(text,_classify_language)
    assert result['detected_language']==language
    assert result['language_routing_status']==('supported' if language in {'en','es'} else 'unsupported')
    assert not any('confidence' in key or 'probability' in key for key in result)


@pytest.mark.parametrize('text',[ENGLISH+'\n\n'+SPANISH,SPANISH+'\n\n'+ENGLISH,(ENGLISH.replace('.','')+' ')*4+(SPANISH.replace('.','')+' ')*4])
def test_substantial_bilingual_content_abstains(text):
    result=route_email_language(text,_classify_language)
    assert result['language_routing_status']=='mixed'
    assert result['detected_language']=='mixed'


@pytest.mark.parametrize('text',['','hello','Microsoft Teams','Verifique su cuenta'])
def test_short_language_remains_undetermined(text):
    assert route_email_language(text,_classify_language)['language_routing_status']=='too_short'


def test_uncertain_and_failed_identifier_abstain_without_details():
    assert route_email_language(ENGLISH,lambda value:('en',.70))['language_routing_status']=='uncertain'
    def fail(value):raise ValueError('private failure')
    result=route_email_language(ENGLISH,fail)
    assert result['language_routing_status']=='uncertain' and 'private' not in result['reason']


def test_single_small_conflicting_fragment_does_not_veto_whole_message():
    text=ENGLISH*6+' A brief ambiguous fragment with several invented tokens.'
    full=prepare_language_text(text)
    windows=language_windows(full)
    def classify(value):return ('fr',.999) if value==windows[-1] else ('en',.999)
    assert route_email_language(text,classify)['language_routing_status']=='supported'


def test_inert_html_and_urls_do_not_dominate_language_features():
    cleaned=prepare_language_text('<html><body><p>'+ENGLISH+'</p><script>русский текст</script><img src="https://foreign.example.test/image"></body></html>')
    assert 'русский' not in cleaned and 'foreign' not in cleaned
    assert route_email_language(cleaned,_classify_language)['detected_language']=='en'
    anchor=prepare_language_text('<a href="https://not-opened.example.test/">Visible anchor words remain readable.</a>')
    assert 'visible anchor words remain readable' in anchor


def test_windows_are_bounded_and_nonoverlapping_for_long_text():
    text=' '.join('word'+str(i) for i in range(2000))
    windows=language_windows(text)
    assert len(windows)<=12
    assert len(' '.join(windows).split())==len(set(' '.join(windows).split()))
