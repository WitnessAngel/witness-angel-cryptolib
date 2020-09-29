Sensor
==========

This module provides base classes to create sensors (gps, gyroscope, audio, video...) and aggregate their data.


Aggregation of records into binary archives
-----------------------------------------------

.. autoclass:: wacryptolib.sensor.TarfileRecordsAggregator


Base classes for poller/pusher sensors
---------------------------------------------

.. autoclass:: wacryptolib.sensor.JsonDataAggregator

.. autoclass:: wacryptolib.sensor.PeriodicValuePoller


Management of multiple sensors simultaneously
------------------------------------------------

.. autoclass:: wacryptolib.sensor.SensorsManager
