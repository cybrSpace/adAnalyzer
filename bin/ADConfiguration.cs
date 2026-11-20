using System;

namespace ADAnalyzer
{
    // Public methods deliberately expose no automatically serialized properties.
    // This is a serialization contract, not an access-control boundary.
    public sealed class ConfigurationState
    {
        private readonly object profile;

        public ConfigurationState(object profile)
        {
            if (profile == null)
            {
                throw new ArgumentNullException("profile");
            }

            this.profile = profile;
        }

        public object GetProfile()
        {
            return this.profile;
        }
    }

    // Reusable internal state without properties that serializers enumerate.
    public sealed class InternalState
    {
        private readonly object value;

        public InternalState(object value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            this.value = value;
        }

        public object GetValue()
        {
            return this.value;
        }
    }
}
