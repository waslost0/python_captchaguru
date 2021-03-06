# Сервер для отправки данных
url_request_captchaguru = "http://api.captcha.guru/in.php"
# Сервер для получения ответа
url_response_captchaguru = "http://api.captcha.guru/res.php"
# ключ приложения
app_key = "111680"


"""
JSON возвращаемы пользователю после решения капчи

serverAnswer - ответ сервера при использовании RuCaptchaControl
captchaSolve - решение капчи,
taskId - находится Id задачи на решение капчи,
         можно использовать при жалобах и прочем,
error - False - если всё хорошо, True - если есть ошибка,
errorBody - полная информация об ошибке:
    {
        text - Развернётое пояснение ошибки
        id - уникальный номер ошибка в ЭТОЙ бибилотеке
    }
"""
JSON_RESPONSE = {
    "serverAnswer": {},
    "captchaSolve": {},
    "taskId": None,
    "error": False,
    "errorBody": {"text": None, "id": 0},
}


# генератор в котором задаётся кол-во поптыок на повторное подключение
def connect_generator():
    for i in range(5):
        yield i
