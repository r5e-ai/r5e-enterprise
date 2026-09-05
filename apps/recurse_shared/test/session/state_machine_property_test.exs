defmodule Recurse.Shared.Session.StateMachinePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.Session.StateMachine

  describe "transition/2 (FR-044 allow-table)" do
    property "only documented transitions succeed; everything else is :invalid_transition" do
      states = StateMachine.states()
      allowed = MapSet.new(StateMachine.transitions())

      check all(
              from <- StreamData.member_of(states),
              to <- StreamData.member_of(states)
            ) do
        case StateMachine.transition(from, to) do
          {:ok, ^to} ->
            assert {from, to} in allowed

          {:error, :invalid_transition} ->
            refute {from, to} in allowed
        end
      end
    end

    property "can_transition?/2 agrees with transition/2" do
      states = StateMachine.states()

      check all(
              from <- StreamData.member_of(states),
              to <- StreamData.member_of(states)
            ) do
        case StateMachine.can_transition?(from, to) do
          true -> assert StateMachine.transition(from, to) == {:ok, to}
          false -> assert StateMachine.transition(from, to) == {:error, :invalid_transition}
        end
      end
    end
  end

  describe "terminal states" do
    test "have no outgoing transitions" do
      terminal = MapSet.new(StateMachine.terminal_states())
      all_transitions = StateMachine.transitions()

      offending =
        Enum.filter(all_transitions, fn {from, _to} -> from in terminal end)

      assert offending == [], "terminal states must not transition: #{inspect(offending)}"
    end
  end

  describe "explicit FR-044 coverage" do
    test "active ↔ interim_committed" do
      assert {:ok, :interim_committed} = StateMachine.transition(:active, :interim_committed)
      assert {:ok, :active} = StateMachine.transition(:interim_committed, :active)
    end

    test "active → commit_retry → commit_retry_exhausted | interim_committed" do
      assert {:ok, :commit_retry} = StateMachine.transition(:active, :commit_retry)

      assert {:ok, :commit_retry_exhausted} =
               StateMachine.transition(:commit_retry, :commit_retry_exhausted)

      assert {:ok, :interim_committed} =
               StateMachine.transition(:commit_retry, :interim_committed)
    end

    test "interim_committed → committed (terminal)" do
      assert {:ok, :committed} = StateMachine.transition(:interim_committed, :committed)
      assert {:error, :invalid_transition} = StateMachine.transition(:committed, :active)
    end

    test "any non-terminal state → cancelled | aborted" do
      for state <- [:active, :interim_committed, :commit_retry, :commit_retry_exhausted] do
        assert {:ok, :cancelled} = StateMachine.transition(state, :cancelled)
        assert {:ok, :aborted} = StateMachine.transition(state, :aborted)
      end
    end
  end
end
