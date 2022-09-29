Sensor
==========

This module provides base classes to create sensors (gps, gyroscope, audio, video...) and aggregate/push their data towards cryptainers.


Aggregation of records into binary archives
++++++++++++++++++++++++++++++++++++++++++++++++++

.. autoclass:: wacryptolib.sensor.TarfileRecordAggregator


Base classes for poller/pusher sensors
++++++++++++++++++++++++++++++++++++++++++++++++++

.. autoclass:: wacryptolib.sensor.JsonDataAggregator

.. autoclass:: wacryptolib.sensor.PeriodicValuePoller


Simultaneous management of multiple sensors
++++++++++++++++++++++++++++++++++++++++++++++++++

.. autoclass:: wacryptolib.sensor.SensorManager
