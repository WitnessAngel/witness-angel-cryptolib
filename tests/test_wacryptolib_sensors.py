from datetime import timedelta

from freezegun import freeze_time

from wacryptolib.container import TimeLimitedAggregatorMixin


def test_time_limited_aggregator_mixin():

    for max_duration_s in (0.5, 20, 1000000):

        delta_seconds = max_duration_s / 3

        with freeze_time() as frozen_datetime:

            obj = TimeLimitedAggregatorMixin(max_duration_s=max_duration_s)
            assert obj._current_start_time is None

            obj._notify_aggregation_operation()
            assert obj._current_start_time

            start_time_copy = obj._current_start_time

            frozen_datetime.tick(delta=timedelta(seconds=delta_seconds))
            obj._notify_aggregation_operation()
            assert obj._current_start_time == start_time_copy

            frozen_datetime.tick(delta=timedelta(seconds=delta_seconds))
            obj._notify_aggregation_operation()
            assert obj._current_start_time == start_time_copy

            frozen_datetime.tick(delta=timedelta(seconds=1.3 * delta_seconds))
            obj._notify_aggregation_operation()
            assert obj._current_start_time > start_time_copy  # Renewed

            obj._flush_aggregated_data()
            assert obj._current_start_time is None
