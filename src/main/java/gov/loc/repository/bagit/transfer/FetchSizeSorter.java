package gov.loc.repository.bagit.transfer;

import gov.loc.repository.bagit.FetchTxt;
import gov.loc.repository.bagit.FetchTxt.FilenameSizeUrl;

import java.io.Serializable;
import java.util.Comparator;

class FetchSizeSorter implements Comparator<FetchTxt.FilenameSizeUrl>, Serializable
{
    private static final long serialVersionUID = 1L;

    @Override
    public int compare(FilenameSizeUrl left, FilenameSizeUrl right)
    {
        Long leftSize = left.getSize();
        Long rightSize = right.getSize();
        int result;
        
        if (leftSize == null){
            if (rightSize == null){
                result = 0;
            }
            else{
                result = -1;
            }
        }
        else{
            if (rightSize == null){
                result = 1;
            }
            else{
                result = leftSize.compareTo(rightSize);
            }
        }
        
        return result;
    }
}