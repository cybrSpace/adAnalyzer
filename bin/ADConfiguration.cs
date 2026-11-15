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
}
