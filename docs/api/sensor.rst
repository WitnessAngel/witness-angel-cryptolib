Sensor
==========

This module provides base classes to create sensors (gps, gyroscope, audio, video...) and aggregate their data.


Aggregation of records into binary archives
-----------------------------------------------

.. autoclass:: wacryptolib.sensor.TarfileAggregator
    :members:


Base classes for poll/push sensors
---------------------------------------------

.. autoclass:: wacryptolib.sensor.JsonAggregator
    :members:

.. autoclass:: wacryptolib.sensor.SensorStateMachineBase
    :members:

.. autoclass:: wacryptolib.sensor.PeriodicValueSensorBase
    :members:

.. autoclass:: wacryptolib.sensor.PeriodicValuePoller
    :members:


Management of multiple sensors simultaneously
------------------------------------------------

.. autoclass:: wacryptolib.sensor.SensorManager
    :members:
