# coding: utf-8
from __future__ import unicode_literals
import hashlib

import requests
from asn1crypto.cms import ContentInfo  # noqa
from asn1crypto.tsp import TimeStampReq, TimeStampResp

from .exceptions import BDoc2Error


class TSAError(BDoc2Error):
    pass


class TSA(object):
    """
    Query a Time Stamping Authority (TSA) for a signature time stamp
    """
    DEMO_URL = 'http://demo.sk.ee/tsa/'
    PROD_URL = 'http://tsa.sk.ee'
    REQUEST_CONTENT_TYPE = 'application/timestamp-query'
    RESPONSE_CONTENT_TYPE = 'application/timestamp-reply'

    def __init__(self, url=None):
        self.url = self.PROD_URL if url is None else url
        self.ts_response = None

    def get_timestamp(self, message):
        """Get the time stamp structure for embedding in a XAdES signature

        How to prepare the message:
        https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
        section 7.3

        :param bytes message:
        :return: ContentInfo
        """
        request = TimeStampReq({
            'version': 'v1',
            'message_imprint': {
                'hash_algorithm': {
                    'algorithm': 'sha256'
                },
                'hashed_message': hashlib.sha256(message).digest(),
            },
            'cert_req': True,  # Need the TSA cert in the response for validation
        })

        try:
            response = requests.post(
                self.url,
                data=request.dump(),
                headers={
                    'Content-Type': self.REQUEST_CONTENT_TYPE,
                    'Connection': 'close',
                }
            )
            response.raise_for_status()
        except requests.ConnectionError:
            raise TSA("Failed to connect to TSA service at {}".format(self.url))
        except requests.HTTPError as e:
            raise TSAError("Bad response from TSA service at {}: {}".format(self.url, e))

        assert response.status_code == 200
        assert response.headers['Content-Type'] == self.RESPONSE_CONTENT_TYPE

        ts_response = TimeStampResp.load(response.content)
        assert ts_response['status']['status_string'][0].native == 'Operation Okay'

        self.ts_response = ts_response
        return ts_response['time_stamp_token']
