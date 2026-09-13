#
# Copyright (C) 2023 DANS - Data Archiving and Networked Services (info@dans.knaw.nl)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

echo "Delomboking first, so that getters and setters will appear in JavaDocs"
mvn clean lombok:delombok
echo "Calling JavaDoc"
mvn javadoc:javadoc
echo "Removing existing JavaDocs if present"
if [ -d "docs/javadocs" ]; then rm -fr docs/javadocs; fi
echo "Moving newly generated JavaDocs in place"
mv target/reports/apidocs docs/javadocs
echo "DONE build and add javadocs"



