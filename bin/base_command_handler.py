import app_greynoise_declare # noqa # pylint: disable=unused-import
import traceback

from requests.exceptions import ConnectionError, RequestException
from splunklib.binding import HTTPError
from splunklib.searchcommands import GeneratingCommand
from greynoise.exceptions import RateLimitError, RequestFailure

from greynoise_exceptions import APIKeyNotFoundError
import utility


class BaseCommandHandler(GeneratingCommand):
    """Base custom command handler class to handle all the exceptions and duplicate code at one place.

    When python script of custom command executes, generate method will be called, and after executing the common code,
    it will call the custom `do_generate` method from the respective command's python script.
    """

    def generate(self):
        """Method which calls the custom `do_generate` method that yields records to the Splunk processing pipeline."""
        try:
            # Setup logger
            logger = utility.setup_logger(
                session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command
            )

            try:
                message = ''
                api_key = utility.get_api_key(self._metadata.searchinfo.session_key, logger=logger)
            except APIKeyNotFoundError as e:
                message = str(e)
            except HTTPError as e:
                message = str(e)

            if message:
                logger.error("Error occured while retrieving API key, Error: {}".format(message))
                self.write_error(message)
                exit(1)

            # This will call the do_generate method of the respective class from which this class was called
            # And generate the events
            for event in self.do_generate(api_key, logger):
                yield event

        except RateLimitError:
            logger.error("Rate limit error occured while executing the custom command.")
            self.write_error("The Rate Limit has been exceeded. Please contact the Administrator")
        except RequestFailure as e:

            response_code, response_message = e.args
            if response_code == 401:
                msg = "Unauthorized. Please check your API key."
            else:
                # Need to handle this, as splunklib is unable to handle the exception with
                # (400, {'error': 'error_reason'}) format
                msg = ("The API call to the GreyNoise platform have been failed "
                       "with status_code: {} and error: {}").format(
                    response_code, response_message['error'] if isinstance(response_message, dict)
                    else response_message)

            logger.error("{}".format(str(msg)))
            self.write_error(msg)
        except ConnectionError:
            logger.error("Error while connecting to the Server. Please check your connection and try again.")
            self.write_error("Error while connecting to the Server. Please check your connection and try again.")
        except RequestException:
            logger.error(
                "There was an ambiguous exception that occurred while handling your Request. Please try again.")
            self.write_error(
                "There was an ambiguous exception that occurred while handling your Request. Please try again.")
        except Exception:
            logger.error(
                "Exception occured while executing the custom command, Exception: {} ".format(
                    str(traceback.format_exc())))
            self.write_error(
                "Exception occured while executing the {custom_command} custom command. "
                "See greynoise_main.log for more details."
                .format(custom_command=str(self._metadata.searchinfo.command)))

    def do_generate(self, api_key, logger):
        """Method that yields records to the Splunk processing pipeline."""
        raise NotImplementedError()
