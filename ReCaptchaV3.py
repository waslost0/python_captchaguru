import time
import requests

from CaptchaGuru.decorators import api_key_check
from CaptchaGuru.result_handler import get_sync_result, get_async_result
from CaptchaGuru.config import url_request_captchaguru, url_response_captchaguru, JSON_RESPONSE


class ReCaptchaV3:
    def __init__(
        self,
        captchaguru_key,
        sleep_time: int = 10,
        action: str = "verify",
        min_score: float = 0.4,
        proxy: str = None,
        proxytype: str = None,
        **kwargs,
    ):
        """
		Инициализация нужных переменных.
		:param captchaguru_key:  АПИ ключ капчи из кабинета пользователя
		:param sleep_time: Вермя ожидания решения капчи
		:param action: Значение параметра action, которые вы нашли в коде сайта
		:param min_score: Требуемое значение рейтинга (score)
		:param proxy: Для решения рекапчи через прокси - передаётся прокси и данные для аутентификации.
		                ` логин:пароль@IP_адрес:ПОРТ` / `login:password@IP:port`.
		:param proxytype: Тип используемого прокси. Доступные: `HTTP`, `HTTPS`, `SOCKS4`, `SOCKS5`.
		:param kwargs: Для передачи дополнительных параметров
		"""
        # время ожидания решения капчи
        self.sleep_time = sleep_time

        # ссылка для запроса
        self.url_request = url_request_captchaguru

        # ссылка для ответа
        self.url_response = url_response_captchaguru

        # результат ответа сервиса
        self.result = JSON_RESPONSE.copy()

        # проверка допустимости переданного параметра для рейтинга
        if not 0.1 < min_score < 0.9:
            raise ValueError(
                f"\nПараметр `min_score` должен быть от `0.1` до `0.9`. \n\tВы передали - {min_score}"
            )
        # пайлоад POST запроса на отправку капчи на сервер
        self.post_payload = {
            "key": captchaguru_key,
            "method": "userrecaptcha",
            "version": "v3",
            "json": 1,
            "action": action,
            "min_score": min_score,
        }

        # Если переданы ещё параметры - вносим их в post_payload
        if kwargs:
            for key in kwargs:
                self.post_payload.update({key: kwargs[key]})

        # добавление прокси для решения капчи с того же IP
        if proxy and proxytype:
            self.post_payload.update({"proxy": proxy, "proxytype": proxytype})

        # пайлоад GET запроса на получение результата решения капчи
        self.get_payload = {"key": captchaguru_key, "action": "get", "json": 1, "taskinfo": 1}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            return False
        return True

    @api_key_check
    def captcha_handler(self, site_key: str, page_url: str, **kwargs):
        """
		Метод отвечает за передачу данных на сервер для решения капчи
		:param site_key: Гугл-ключ сайта
		:param page_url: Ссылка на страницу на которой находится капча
		:param kwargs: Для передачи дополнительных параметров

		:return: Ответ на капчу в виде JSON строки с полями:
                    captchaSolve - решение капчи,
                    user_check - ID работника, который решил капчу
                    user_score -  score решившего капчу работника
                    taskId - находится ID задачи на решение капчи, можно использовать при жалобах и прочем,
                    error - False - если всё хорошо, True - если есть ошибка,
                    errorBody - название ошибки		
		"""

        # Если переданы ещё параметры - вносим их в post_payload
        if kwargs:
            for key in kwargs:
                self.post_payload.update({key: kwargs[key]})

        self.post_payload.update({"googlekey": site_key, "pageurl": page_url})
        # получаем ID капчи
        captcha_id = requests.post(self.url_request, data=self.post_payload).json()

        # если вернулся ответ с ошибкой то записываем её и возвращаем результат
        if captcha_id["status"] == 0:
            self.result.update({"error": True, "errorBody": captcha_id["request"]})
            return self.result
        # иначе берём ключ отправленной на решение капчи и ждём решения
        else:
            captcha_id = captcha_id["request"]
            # вписываем в taskId ключ отправленной на решение капчи
            self.result.update({"taskId": captcha_id})
            # обновляем пайлоад, вносим в него ключ отправленной на решение капчи
            # и параметр `taskinfo=1` для получения подробной информации об исполнителе
            self.get_payload.update({"id": captcha_id})

            # если передан параметр `pingback` - не ждём решения капчи а возвращаем незаполненный ответ
            if self.post_payload.get("pingback"):
                return self.get_payload
            else:
                # Ожидаем решения капчи 10 секунд
                time.sleep(self.sleep_time)
                return get_sync_result(
                    get_payload=self.get_payload,
                    sleep_time=self.sleep_time,
                    url_response=self.url_response,
                    result=self.result,
                )
